package keyvault

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"time"
)

// rotateBatchSize bounds the rows re-encrypted in a single transaction, so
// concurrent operations are never blocked longer than one batch.
const rotateBatchSize = 500

// rotateBatchPause, when > 0, makes rotateBatches sleep between batches.
// Test-only hook to widen the crash window; always zero in production.
var rotateBatchPause time.Duration

// RotateMaster switches the vault to a new master key derived from
// newPassphrase. Every stored ciphertext is re-encrypted under it, in
// bounded batches; other operations proceed concurrently.
//
// Crash safety: the meta switch (new salt/verifier/epoch plus an escrow of
// the old master key encrypted under the new one) commits atomically before
// any record is touched. If the process dies, Open with the new passphrase
// resumes and completes the rotation; the old passphrase is invalid from
// the moment the meta switch commits.
func (v *Vault) RotateMaster(newPassphrase string) error {
	salt := make([]byte, kdfSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	newMK, err := deriveMasterKey(newPassphrase, salt, kdfIterations)
	if err != nil {
		return err
	}

	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return ErrVaultClosed
	}
	if v.rotating {
		v.mu.Unlock()
		return fmt.Errorf("keyvault: rotation already in progress")
	}
	oldEpoch := v.writeEpoch
	newEpoch := oldEpoch + 1
	oldMK := v.masterKeys[oldEpoch]

	escrowNonce, escrowCT, err := encryptBlob(newMK, oldMK)
	if err != nil {
		v.mu.Unlock()
		return err
	}
	verifyNonce, verifyCT, err := encryptBlob(newMK, verifyPlaintext)
	if err != nil {
		v.mu.Unlock()
		return err
	}

	tx, err := v.db.Begin()
	if err != nil {
		v.mu.Unlock()
		return err
	}
	pairs := map[string][]byte{
		metaKDFSalt:     salt,
		metaKDFIters:    []byte(strconv.Itoa(kdfIterations)),
		metaVerifyNonce: verifyNonce,
		metaVerifyCT:    verifyCT,
		metaEpoch:       []byte(strconv.FormatUint(newEpoch, 10)),
		metaState:       []byte(stateRotating),
		metaEscrowNonce: escrowNonce,
		metaEscrowCT:    escrowCT,
	}
	for k, val := range pairs {
		if err := metaSet(tx, k, val); err != nil {
			tx.Rollback()
			v.mu.Unlock()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		v.mu.Unlock()
		return err
	}
	v.masterKeys[newEpoch] = newMK
	v.writeEpoch = newEpoch
	v.rotating = true
	v.mu.Unlock()

	if err := v.rotateBatches(oldEpoch); err != nil {
		return err
	}
	return v.finalizeRotation(oldEpoch)
}

// rotateBatches re-encrypts every row still at oldEpoch under the master
// key of oldEpoch+1, one bounded batch per transaction.
func (v *Vault) rotateBatches(oldEpoch uint64) error {
	for {
		n, err := v.rotateBatch(oldEpoch)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if rotateBatchPause > 0 {
			time.Sleep(rotateBatchPause)
		}
	}
}

func (v *Vault) rotateBatch(oldEpoch uint64) (int, error) {
	v.mu.RLock()
	oldMK := v.masterKeys[oldEpoch]
	newMK := v.masterKeys[oldEpoch+1]
	v.mu.RUnlock()
	if oldMK == nil || newMK == nil {
		return 0, fmt.Errorf("keyvault: missing master keys for rotation at epoch %d", oldEpoch)
	}

	rows, err := v.db.Query(`SELECT id, nonce, ct FROM keys WHERE epoch = ? LIMIT ?`,
		oldEpoch, rotateBatchSize)
	if err != nil {
		return 0, err
	}
	type rekeyed struct {
		id        string
		nonce, ct []byte
	}
	var items []rekeyed
	for rows.Next() {
		var id string
		var nonce, ct []byte
		if err := rows.Scan(&id, &nonce, &ct); err != nil {
			rows.Close()
			return 0, err
		}
		plain, err := decryptBlob(oldMK, nonce, ct)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("keyvault: cannot decrypt key %s during rotation: %w", id, err)
		}
		newNonce, newCT, err := encryptBlob(newMK, plain)
		zeroBytes(plain)
		if err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, rekeyed{id: id, nonce: newNonce, ct: newCT})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	if len(items) == 0 {
		return 0, nil
	}
	tx, err := v.db.Begin()
	if err != nil {
		return 0, err
	}
	newEpoch := oldEpoch + 1
	for _, it := range items {
		// The epoch guard makes the update a no-op if the row was
		// destroyed (or otherwise changed) after our SELECT.
		if _, err := tx.Exec(
			`UPDATE keys SET epoch = ?, nonce = ?, ct = ? WHERE id = ? AND epoch = ?`,
			newEpoch, it.nonce, it.ct, it.id, oldEpoch); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}

// finalizeRotation commits the end of a rotation: the escrow is deleted so
// no form of the old master key remains in the database, and the old master
// key is dropped from memory.
func (v *Vault) finalizeRotation(oldEpoch uint64) error {
	tx, err := v.db.Begin()
	if err != nil {
		return err
	}
	if err := metaSet(tx, metaState, []byte(stateNormal)); err != nil {
		tx.Rollback()
		return err
	}
	if err := metaDel(tx, metaEscrowNonce); err != nil {
		tx.Rollback()
		return err
	}
	if err := metaDel(tx, metaEscrowCT); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	v.mu.Lock()
	if old, ok := v.masterKeys[oldEpoch]; ok {
		zeroBytes(old)
		delete(v.masterKeys, oldEpoch)
	}
	v.rotating = false
	v.mu.Unlock()
	return nil
}
