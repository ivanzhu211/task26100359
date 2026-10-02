package keyvault

import (
	"crypto/rand"
	"database/sql"
	"fmt"
)

// ErrKeyNotFound is returned when a key id does not exist (or was destroyed).
var ErrKeyNotFound = fmt.Errorf("keyvault: key not found")

// ErrVaultClosed is returned when operating on a closed vault.
var ErrVaultClosed = fmt.Errorf("keyvault: vault is closed")

// CreateKey generates a new key with a random 32-byte material and returns
// its UUID. During a rotation the key is encrypted under the new master key.
func (v *Vault) CreateKey() (string, error) {
	material := make([]byte, keyMaterialLen)
	if _, err := rand.Read(material); err != nil {
		return "", err
	}
	id := newUUID()

	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return "", ErrVaultClosed
	}
	mk, ok := v.masterKeys[v.writeEpoch]
	if !ok {
		return "", fmt.Errorf("keyvault: no master key for epoch %d", v.writeEpoch)
	}
	nonce, ct, err := encryptBlob(mk, material)
	if err != nil {
		return "", err
	}
	_, err = v.db.Exec(`INSERT INTO keys(id, epoch, nonce, ct) VALUES(?, ?, ?, ?)`,
		id, v.writeEpoch, nonce, ct)
	if err != nil {
		return "", err
	}
	return id, nil
}

// GetMaterial returns the plaintext material of the key with the given id.
func (v *Vault) GetMaterial(id string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrVaultClosed
	}
	var epoch uint64
	var nonce, ct []byte
	err := v.db.QueryRow(`SELECT epoch, nonce, ct FROM keys WHERE id = ?`, id).
		Scan(&epoch, &nonce, &ct)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	mk, ok := v.masterKeys[epoch]
	if !ok {
		return nil, fmt.Errorf("keyvault: no master key for epoch %d", epoch)
	}
	return decryptBlob(mk, nonce, ct)
}

// DestroyKey permanently destroys the key with the given id.
func (v *Vault) DestroyKey(id string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return ErrVaultClosed
	}
	res, err := v.db.Exec(`DELETE FROM keys WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrKeyNotFound
	}
	return nil
}

// newUUID returns a random RFC 4122 version 4 UUID.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
