package vault

import (
	"errors"
)

const rotationBatchSize = 256

// RotateMaster re-encrypts every key record under a fresh master key derived
// from newPassphrase. It runs in small transactions so CreateKey, GetMaterial
// and DestroyKey keep working throughout.
func (v *Vault) RotateMaster(newPassphrase string) error {
	salt, err := randomBytes(saltLen)
	if err != nil {
		return err
	}
	newKey, err := deriveKey(newPassphrase, salt, kdfIterations)
	if err != nil {
		return err
	}
	verNonce, verCT, err := seal(&newKey, verifierPlain)
	if err != nil {
		return err
	}

	// Begin: publish rotation state atomically, then arm the in-memory key.
	v.mu.Lock()
	if v.nxt != nil {
		v.mu.Unlock()
		return errors.New("vault: rotation already in progress")
	}
	// Wrap the current master key under the new one so that, after a crash,
	// Open with the new passphrase can finish the rotation. This is safe:
	// anyone holding the pre-rotation memory dump cannot decrypt it, and it
	// is deleted at finalize.
	recNonce, recCT, err := seal(&newKey, v.cur.key[:])
	if err != nil {
		v.mu.Unlock()
		return err
	}
	tx, err := v.db.Begin()
	if err != nil {
		v.mu.Unlock()
		return err
	}
	newGen := v.cur.gen + 1
	for _, kv := range [][2][]byte{
		{[]byte("rot_gen"), intToBytes(newGen)},
		{[]byte("rot_salt"), salt},
		{[]byte("rot_iter"), intToBytes(kdfIterations)},
		{[]byte("rot_verifier_nonce"), verNonce},
		{[]byte("rot_verifier_ct"), verCT},
		{[]byte("rot_recovery_nonce"), recNonce},
		{[]byte("rot_recovery_ct"), recCT},
	} {
		if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES(?,?)`, string(kv[0]), kv[1]); err != nil {
			tx.Rollback()
			v.mu.Unlock()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		v.mu.Unlock()
		return err
	}
	v.nxt = &masterKey{key: newKey, gen: newGen}
	v.mu.Unlock()

	return v.finishRotation()
}

// rotateBatches re-encrypts all rows from v.cur.gen to v.nxt.gen,
// one small transaction per batch.
func (v *Vault) rotateBatches() error {
	for {
		done, err := v.rotateOneBatch()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func (v *Vault) rotateOneBatch() (done bool, err error) {
	v.mu.RLock()
	cur, nxt := v.cur, v.nxt
	v.mu.RUnlock()
	if nxt == nil {
		return false, errors.New("vault: no rotation in progress")
	}

	tx, err := v.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id,nonce,ct FROM keys WHERE gen=? LIMIT ?`, cur.gen, rotationBatchSize)
	if err != nil {
		return false, err
	}
	type row struct {
		id        string
		nonce, ct []byte
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.nonce, &r.ct); err != nil {
			rows.Close()
			return false, err
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	if len(batch) == 0 {
		return true, nil
	}

	for _, r := range batch {
		plain, err := open(&cur.key, r.nonce, r.ct)
		if err != nil {
			return false, err
		}
		nonce, ct, err := seal(&nxt.key, plain)
		if err != nil {
			return false, err
		}
		if _, err := tx.Exec(`UPDATE keys SET gen=?,nonce=?,ct=? WHERE id=?`, nxt.gen, nonce, ct, r.id); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return false, nil
}

// finalizeRotation promotes the rotation target to be the only master key.
func (v *Vault) finalizeRotation() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	tx, err := v.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var remaining int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM keys WHERE gen=?`, v.cur.gen).Scan(&remaining); err != nil {
		return err
	}
	if remaining > 0 {
		// A row slipped in concurrently; keep rotating.
		return errRotationNotDone
	}

	rot, err := loadRotationState(tx)
	if err != nil {
		return err
	}
	if rot == nil || rot.gen != v.nxt.gen {
		return errors.New("vault: rotation state mismatch")
	}
	for _, kv := range [][2][]byte{
		{[]byte("salt"), rot.salt},
		{[]byte("iter"), intToBytes(rot.iter)},
		{[]byte("verifier_nonce"), rot.verNonce},
		{[]byte("verifier_ct"), rot.verCT},
		{[]byte("gen"), intToBytes(rot.gen)},
	} {
		if err := setMeta(tx, string(kv[0]), kv[1]); err != nil {
			return err
		}
	}
	for _, k := range []string{"rot_gen", "rot_salt", "rot_iter", "rot_verifier_nonce", "rot_verifier_ct", "rot_recovery_nonce", "rot_recovery_ct"} {
		if err := delMeta(tx, k); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	v.cur = v.nxt
	v.nxt = nil
	return nil
}

var errRotationNotDone = errors.New("vault: rotation not done")

// finishRotation completes an interrupted rotation after Open; no other
// goroutines are running yet, so it just drives the same machinery.
func (v *Vault) finishRotation() error {
	if err := v.rotateBatches(); err != nil {
		return err
	}
	for {
		err := v.finalizeRotation()
		if err == errRotationNotDone {
			if err := v.rotateBatches(); err != nil {
				return err
			}
			continue
		}
		return err
	}
}
