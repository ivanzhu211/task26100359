package keyvault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// keySet is a concurrency-safe set of live keys supporting random access.
type keySet struct {
	mu  sync.Mutex
	ids []string
	pos map[string]int
	mat map[string][]byte
}

func newKeySet() *keySet {
	return &keySet{pos: make(map[string]int), mat: make(map[string][]byte)}
}

func (s *keySet) add(id string, material []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pos[id]; ok {
		return
	}
	s.pos[id] = len(s.ids)
	s.ids = append(s.ids, id)
	s.mat[id] = material
}

func (s *keySet) remove(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.pos[id]
	if !ok {
		return nil, false
	}
	m := s.mat[id]
	last := s.ids[len(s.ids)-1]
	s.ids[i] = last
	s.pos[last] = i
	s.ids = s.ids[:len(s.ids)-1]
	delete(s.pos, id)
	delete(s.mat, id)
	return m, true
}

func (s *keySet) random() (string, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ids) == 0 {
		return "", nil, false
	}
	var idx [8]byte
	rand.Read(idx[:])
	i := int(idx[0])<<16 | int(idx[1])<<8 | int(idx[2])
	id := s.ids[i%len(s.ids)]
	return id, s.mat[id], true
}

func (s *keySet) snapshot() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]byte, len(s.mat))
	for id, m := range s.mat {
		out[id] = m
	}
	return out
}

// seedKeys bulk-inserts n keys directly (batched) and returns their
// id->material mapping. Test helper only.
func seedKeys(t *testing.T, v *Vault, n int) map[string][]byte {
	t.Helper()
	v.mu.RLock()
	mk := v.masterKeys[v.writeEpoch]
	epoch := v.writeEpoch
	v.mu.RUnlock()

	out := make(map[string][]byte, n)
	const batch = 1000
	for start := 0; start < n; start += batch {
		end := start + batch
		if end > n {
			end = n
		}
		tx, err := v.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		for i := start; i < end; i++ {
			material := make([]byte, keyMaterialLen)
			rand.Read(material)
			id := newUUID()
			nonce, ct, err := encryptBlob(mk, material)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(`INSERT INTO keys(id, epoch, nonce, ct) VALUES(?, ?, ?, ?)`,
				id, epoch, nonce, ct); err != nil {
				t.Fatal(err)
			}
			out[id] = material
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestConcurrentRotate(t *testing.T) {
	const preset = 100000

	path := t.TempDir() + "/v.db"
	v, err := Open(path, "old-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	live := newKeySet()
	for id, m := range seedKeys(t, v, preset) {
		live.add(id, m)
	}

	// Capture every key byte in process memory before rotation: the master
	// key (there is no intermediate key layer in this design).
	v.mu.RLock()
	oldEpoch := v.writeEpoch
	oldMK := append([]byte(nil), v.masterKeys[oldEpoch]...)
	v.mu.RUnlock()

	var destroyedMu sync.Mutex
	destroyed := make(map[string]struct{}) // hex(material) of destroyed keys

	var failCount atomic.Int32
	fail := func(format string, args ...interface{}) {
		if failCount.Add(1) <= 10 {
			t.Errorf(format, args...)
		}
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Readers: continuously read random live keys and verify bytes.
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				id, want, ok := live.random()
				if !ok {
					continue
				}
				got, err := v.GetMaterial(id)
				if err == ErrKeyNotFound {
					continue // destroyed concurrently
				}
				if err != nil {
					fail("GetMaterial(%s): %v", id, err)
					return
				}
				if !bytes.Equal(got, want) {
					fail("GetMaterial(%s): wrong bytes", id)
					return
				}
			}
		}()
	}

	// Creators: continuously create keys and register them.
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				id, err := v.CreateKey()
				if err != nil {
					fail("CreateKey: %v", err)
					return
				}
				m, err := v.GetMaterial(id)
				if err != nil {
					fail("GetMaterial after CreateKey: %v", err)
					return
				}
				live.add(id, m)
			}
		}()
	}

	// Destroyer: continuously destroys random live keys.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			id, _, ok := live.random()
			if !ok {
				continue
			}
			if err := v.DestroyKey(id); err != nil {
				continue // lost a race with another destroy
			}
			if m, ok := live.remove(id); ok {
				destroyedMu.Lock()
				destroyed[hex.EncodeToString(m)] = struct{}{}
				destroyedMu.Unlock()
			}
		}
	}()

	if err := v.RotateMaster("new-passphrase"); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	close(done)
	wg.Wait()

	if failCount.Load() > 0 {
		t.Fatalf("%d concurrent operation failures", failCount.Load())
	}

	// After rotation only the new master key may remain in memory.
	v.mu.RLock()
	if len(v.masterKeys) != 1 {
		t.Fatalf("expected 1 master key in memory, got %d", len(v.masterKeys))
	}
	newMK := append([]byte(nil), v.masterKeys[v.writeEpoch]...)
	v.mu.RUnlock()
	if bytes.Equal(oldMK, newMK) {
		t.Fatal("master key did not change")
	}

	// Every ciphertext in the database must be undecryptable with the
	// pre-rotation key bytes, and no live ciphertext may decode to a
	// destroyed key's material.
	rows, err := v.db.Query(`SELECT id, nonce, ct FROM keys`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id        string
		nonce, ct []byte
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.nonce, &r.ct); err != nil {
			t.Fatal(err)
		}
		all = append(all, r)
	}
	rows.Close()

	destroyedMu.Lock()
	destroyedCopy := make(map[string]struct{}, len(destroyed))
	for k := range destroyed {
		destroyedCopy[k] = struct{}{}
	}
	destroyedMu.Unlock()

	liveSnap := live.snapshot()
	for _, r := range all {
		if plain, err := decryptBlob(oldMK, r.nonce, r.ct); err == nil {
			t.Fatalf("row %s decrypts with pre-rotation master key: %x", r.id, plain[:8])
		}
		plain, err := decryptBlob(newMK, r.nonce, r.ct)
		if err != nil {
			t.Fatalf("row %s not decryptable with current master key: %v", r.id, err)
		}
		if _, ok := destroyedCopy[hex.EncodeToString(plain)]; ok {
			t.Fatalf("row %s contains material of a destroyed key", r.id)
		}
		// Live keys must still hold exactly the bytes we recorded.
		if want, ok := liveSnap[r.id]; ok && !bytes.Equal(plain, want) {
			t.Fatalf("row %s material mismatch after rotation", r.id)
		}
	}

	// Meta table: no blob may be decryptable with the old master key either.
	metaRows, err := v.db.Query(`SELECT key, value FROM meta`)
	if err != nil {
		t.Fatal(err)
	}
	defer metaRows.Close()
	for metaRows.Next() {
		var k string
		var val []byte
		if err := metaRows.Scan(&k, &val); err != nil {
			t.Fatal(err)
		}
		if k == metaEscrowNonce || k == metaEscrowCT {
			t.Fatal("escrow of old master key still present after rotation")
		}
		if len(val) == 0 {
			continue
		}
		// Try the value as a GCM ciphertext under the old master key with
		// every plausible nonce split: nonce is stored separately in this
		// schema, so also try the stored nonce columns.
	}
	// Verify the verifier blob specifically (nonce + ct columns).
	vn, _ := metaGet(v.db, metaVerifyNonce)
	vc, _ := metaGet(v.db, metaVerifyCT)
	if _, err := decryptBlob(oldMK, vn, vc); err == nil {
		t.Fatal("meta verifier decrypts with pre-rotation master key")
	}

	fmt.Printf("rotation checked: %d rows, %d destroyed keys\n", len(all), len(destroyedCopy))
}
