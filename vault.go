package vault

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type masterKey struct {
	key [32]byte
	gen int64
}

type Vault struct {
	db  *sql.DB
	mu  sync.RWMutex
	cur *masterKey
	nxt *masterKey // non-nil only while a rotation is in progress
}

// rotationState mirrors the rot_* rows in meta.
type rotationState struct {
	gen      int64
	salt     []byte
	iter     int64
	verNonce []byte
	verCT    []byte
	recNonce []byte
	recCT    []byte
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  gen INTEGER NOT NULL,
  nonce BLOB NOT NULL,
  ct BLOB NOT NULL
) WITHOUT ROWID;
`

func Open(path, passphrase string) (*Vault, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(wal)&_pragma=synchronous(normal)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	v := &Vault{db: db}

	salt, ok, err := getMeta(db, "salt")
	if err != nil {
		db.Close()
		return nil, err
	}
	if !ok {
		// Fresh vault: initialize with this passphrase.
		if err := v.initFresh(passphrase); err != nil {
			db.Close()
			return nil, err
		}
		return v, nil
	}

	iter := bytesToInt(mustMeta(db, "iter"))
	verNonce := mustMeta(db, "verifier_nonce")
	verCT := mustMeta(db, "verifier_ct")
	gen := bytesToInt(mustMeta(db, "gen"))

	rot, err := loadRotationState(db)
	if err != nil {
		db.Close()
		return nil, err
	}

	if rot != nil {
		// Interrupted rotation. Rollback is impossible (rows already
		// converted need the new master key to decrypt), so only the new
		// passphrase opens the vault, rolling the rotation forward.
		nxtKey, derr := deriveKey(passphrase, rot.salt, int(rot.iter))
		if derr == nil && checkVerifier(&nxtKey, rot.verNonce, rot.verCT) {
			curRaw, derr := open(&nxtKey, rot.recNonce, rot.recCT)
			if derr != nil || len(curRaw) != keyLen {
				db.Close()
				return nil, errors.New("vault: corrupt rotation recovery data")
			}
			var curKey [32]byte
			copy(curKey[:], curRaw)
			v.cur = &masterKey{key: curKey, gen: gen}
			v.nxt = &masterKey{key: nxtKey, gen: rot.gen}
			if err := v.finishRotation(); err != nil {
				db.Close()
				return nil, err
			}
			return v, nil
		}
		db.Close()
		return nil, errBadPassphrase
	}

	key, err := deriveKey(passphrase, salt, int(iter))
	if err != nil {
		db.Close()
		return nil, err
	}
	if !checkVerifier(&key, verNonce, verCT) {
		db.Close()
		return nil, errBadPassphrase
	}
	v.cur = &masterKey{key: key, gen: gen}
	return v, nil
}

func (v *Vault) Close() error { return v.db.Close() }

func (v *Vault) initFresh(passphrase string) error {
	salt, err := randomBytes(saltLen)
	if err != nil {
		return err
	}
	key, err := deriveKey(passphrase, salt, kdfIterations)
	if err != nil {
		return err
	}
	verNonce, verCT, err := seal(&key, verifierPlain)
	if err != nil {
		return err
	}
	tx, err := v.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, kv := range [][2][]byte{
		{[]byte("salt"), salt},
		{[]byte("iter"), intToBytes(kdfIterations)},
		{[]byte("verifier_nonce"), verNonce},
		{[]byte("verifier_ct"), verCT},
		{[]byte("gen"), intToBytes(0)},
	} {
		if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?,?)`, string(kv[0]), kv[1]); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	v.cur = &masterKey{key: key, gen: 0}
	return nil
}

// --- meta helpers ---

type queryer interface {
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

func getMeta(q queryer, k string) ([]byte, bool, error) {
	var v []byte
	err := q.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

func setMeta(q queryer, k string, v []byte) error {
	_, err := q.Exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

func delMeta(q queryer, k string) error {
	_, err := q.Exec(`DELETE FROM meta WHERE k=?`, k)
	return err
}

func mustMeta(q queryer, k string) []byte {
	v, ok, err := getMeta(q, k)
	if err != nil || !ok {
		panic(fmt.Sprintf("vault: missing meta key %q (err=%v)", k, err))
	}
	return v
}

func loadRotationState(q queryer) (*rotationState, error) {
	_, ok, err := getMeta(q, "rot_gen")
	if err != nil || !ok {
		return nil, err
	}
	st := &rotationState{
		gen:      bytesToInt(mustMeta(q, "rot_gen")),
		salt:     mustMeta(q, "rot_salt"),
		iter:     bytesToInt(mustMeta(q, "rot_iter")),
		verNonce: mustMeta(q, "rot_verifier_nonce"),
		verCT:    mustMeta(q, "rot_verifier_ct"),
		recNonce: mustMeta(q, "rot_recovery_nonce"),
		recCT:    mustMeta(q, "rot_recovery_ct"),
	}
	return st, nil
}

func intToBytes(n int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return b[:]
}

func bytesToInt(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b))
}

// isBusy reports whether err is a transient SQLite lock conflict.
func isBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "SQLITE_BUSY")
}

// retryBusy reruns fn while SQLite reports transient lock contention.
func retryBusy(fn func() error) error {
	var err error
	for attempt := 0; attempt < 100; attempt++ {
		if err = fn(); !isBusy(err) {
			return err
		}
		time.Sleep(time.Duration(1+attempt) * time.Millisecond)
	}
	return err
}
