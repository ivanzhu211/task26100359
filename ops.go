package vault

import (
	"database/sql"
	"errors"
	"fmt"
)

var ErrKeyNotFound = errors.New("vault: key not found")

const materialLen = 32

// CreateKey generates a new key with random material and returns its ID.
func (v *Vault) CreateKey() (string, error) {
	material, err := randomBytes(materialLen)
	if err != nil {
		return "", err
	}
	id, err := newUUID()
	if err != nil {
		return "", err
	}
	err = retryBusy(func() error { return v.insertKey(id, material) })
	if err != nil {
		return "", err
	}
	return id, nil
}

func (v *Vault) insertKey(id string, material []byte) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	tx, err := v.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Decide generation from DB state inside this transaction so the choice
	// is consistent with concurrent rotation begin/finalize.
	gen := bytesToInt(mustMeta(tx, "gen"))
	mk := v.cur
	if rotGenB, ok, err := getMeta(tx, "rot_gen"); err != nil {
		return err
	} else if ok {
		gen = bytesToInt(rotGenB)
		mk = v.nxt
	}
	if mk == nil {
		return errors.New("vault: inconsistent rotation state")
	}

	nonce, ct, err := seal(&mk.key, material)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO keys(id,gen,nonce,ct) VALUES(?,?,?,?)`, id, gen, nonce, ct); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// GetMaterial returns the plaintext material of a live key.
func (v *Vault) GetMaterial(id string) ([]byte, error) {
	var plain []byte
	err := retryBusy(func() error {
		var err error
		plain, err = v.getMaterial(id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func (v *Vault) getMaterial(id string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var gen int64
	var nonce, ct []byte
	err := v.db.QueryRow(`SELECT gen,nonce,ct FROM keys WHERE id=?`, id).Scan(&gen, &nonce, &ct)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	var mk *masterKey
	switch {
	case gen == v.cur.gen:
		mk = v.cur
	case v.nxt != nil && gen == v.nxt.gen:
		mk = v.nxt
	default:
		return nil, fmt.Errorf("vault: key %s has unknown generation %d", id, gen)
	}
	plain, err := open(&mk.key, nonce, ct)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt key %s: %w", id, err)
	}
	return plain, nil
}

// DestroyKey permanently removes a key.
func (v *Vault) DestroyKey(id string) error {
	return retryBusy(func() error {
		_, err := v.db.Exec(`DELETE FROM keys WHERE id=?`, id)
		return err
	})
}

func newUUID() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
