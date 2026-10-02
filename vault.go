package keyvault

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"fmt"
	"strconv"
	"sync"

	_ "modernc.org/sqlite"
)

// verifyPlaintext is the known plaintext encrypted under the master key to
// verify a passphrase at Open time.
var verifyPlaintext = []byte("keyvault-master-verify-v1")

// Meta keys.
const (
	metaKDFSalt     = "kdf_salt"
	metaKDFIters    = "kdf_iters"
	metaVerifyNonce = "verify_nonce"
	metaVerifyCT    = "verify_ct"
	metaEpoch       = "epoch"
	metaState       = "state"
	metaEscrowNonce = "escrow_nonce"
	metaEscrowCT    = "escrow_ct"
	stateNormal     = "normal"
	stateRotating   = "rotating"
)

// Vault is a local key vault persisted in a single SQLite file.
//
// Concurrency: mu is an RWMutex. Ordinary operations hold RLock for their
// (single, small) transaction; rotation holds Lock only for two short
// metadata sections and RLock for its per-batch work, so concurrent
// operations are blocked at most by one batch.
type Vault struct {
	db *sql.DB

	mu         sync.RWMutex
	masterKeys map[uint64][]byte // epoch -> master key
	writeEpoch uint64            // epoch used for newly created keys
	rotating   bool
	closed     bool
}

// Open opens (or creates) the vault at path. It fails with ErrBadPassphrase
// if the passphrase does not match. If a previous rotation was interrupted
// by a crash, Open completes it before returning.
func Open(path, passphrase string) (*Vault, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	v := &Vault{db: db, masterKeys: make(map[uint64][]byte)}
	if err := v.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	salt, err := metaGet(db, metaKDFSalt)
	if err != nil {
		db.Close()
		return nil, err
	}
	if salt == nil {
		if err := v.initFresh(passphrase); err != nil {
			db.Close()
			return nil, err
		}
		return v, nil
	}

	if err := v.unlock(passphrase, salt); err != nil {
		db.Close()
		return nil, err
	}
	return v, nil
}

// Close closes the vault.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	for epoch, mk := range v.masterKeys {
		zeroBytes(mk)
		delete(v.masterKeys, epoch)
	}
	return v.db.Close()
}

func (v *Vault) initSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY,
			epoch INTEGER NOT NULL,
			nonce BLOB NOT NULL,
			ct BLOB NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_keys_epoch ON keys(epoch)`,
	}
	for _, s := range stmts {
		if _, err := v.db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// initFresh initializes a brand-new vault with a master key derived from
// passphrase.
func (v *Vault) initFresh(passphrase string) error {
	salt := make([]byte, kdfSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	mk, err := deriveMasterKey(passphrase, salt, kdfIterations)
	if err != nil {
		return err
	}
	verifyNonce, verifyCT, err := encryptBlob(mk, verifyPlaintext)
	if err != nil {
		return err
	}

	tx, err := v.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	pairs := map[string][]byte{
		metaKDFSalt:     salt,
		metaKDFIters:    []byte(strconv.Itoa(kdfIterations)),
		metaVerifyNonce: verifyNonce,
		metaVerifyCT:    verifyCT,
		metaEpoch:       []byte("1"),
		metaState:       []byte(stateNormal),
	}
	for k, val := range pairs {
		if err := metaSet(tx, k, val); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	v.masterKeys[1] = mk
	v.writeEpoch = 1
	return nil
}

// unlock verifies the passphrase against the stored meta and loads the
// master key(s). If a rotation was interrupted, it is completed here.
func (v *Vault) unlock(passphrase string, salt []byte) error {
	itersBytes, err := metaGet(v.db, metaKDFIters)
	if err != nil {
		return err
	}
	iters, err := strconv.Atoi(string(itersBytes))
	if err != nil {
		return fmt.Errorf("keyvault: corrupt kdf_iters: %w", err)
	}
	mk, err := deriveMasterKey(passphrase, salt, iters)
	if err != nil {
		return err
	}

	verifyNonce, err := metaGet(v.db, metaVerifyNonce)
	if err != nil {
		return err
	}
	verifyCT, err := metaGet(v.db, metaVerifyCT)
	if err != nil {
		return err
	}
	plain, err := decryptBlob(mk, verifyNonce, verifyCT)
	if err != nil || !bytes.Equal(plain, verifyPlaintext) {
		zeroBytes(mk)
		return ErrBadPassphrase
	}

	epochBytes, err := metaGet(v.db, metaEpoch)
	if err != nil {
		return err
	}
	epoch, err := strconv.ParseUint(string(epochBytes), 10, 64)
	if err != nil {
		return fmt.Errorf("keyvault: corrupt epoch: %w", err)
	}
	state, err := metaGet(v.db, metaState)
	if err != nil {
		return err
	}

	v.masterKeys[epoch] = mk
	v.writeEpoch = epoch

	if string(state) == stateRotating {
		// A rotation was interrupted. The meta already points at the new
		// master key; recover the old one from the escrow and finish the
		// re-encryption before serving operations.
		escrowNonce, err := metaGet(v.db, metaEscrowNonce)
		if err != nil {
			return err
		}
		escrowCT, err := metaGet(v.db, metaEscrowCT)
		if err != nil {
			return err
		}
		oldMK, err := decryptBlob(mk, escrowNonce, escrowCT)
		if err != nil {
			return fmt.Errorf("keyvault: corrupt rotation escrow: %w", err)
		}
		v.masterKeys[epoch-1] = oldMK
		v.rotating = true
		if err := v.rotateBatches(epoch - 1); err != nil {
			return err
		}
		if err := v.finalizeRotation(epoch - 1); err != nil {
			return err
		}
	}
	return nil
}

func metaGet(db *sql.DB, key string) ([]byte, error) {
	var val []byte
	err := db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

func metaSet(tx *sql.Tx, key string, val []byte) error {
	_, err := tx.Exec(`INSERT INTO meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, val)
	return err
}

func metaDel(tx *sql.Tx, key string) error {
	_, err := tx.Exec(`DELETE FROM meta WHERE key = ?`, key)
	return err
}
