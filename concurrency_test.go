package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRotateConcurrent presets >=100k keys, runs RotateMaster while goroutines
// hammer CreateKey/GetMaterial/DestroyKey, then verifies:
//   - no ciphertext in the DB is decryptable by the pre-rotation master key
//   - every live key decrypts to the right bytes under the current master key
//   - no destroyed key's material reappears
func TestRotateConcurrent(t *testing.T) {
	const preset = 100000

	db := filepath.Join(t.TempDir(), "v.db")
	v, err := Open(db, "old-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	var matsMu sync.RWMutex
	mats := make(map[string][]byte, preset) // every key ever created
	destroyed := make(map[string][]byte)    // material of destroyed keys
	presetIDs := make([]string, 0, preset)

	for i := 0; i < preset; i++ {
		id, err := v.CreateKey()
		if err != nil {
			t.Fatalf("preset create %d: %v", i, err)
		}
		m, err := v.GetMaterial(id)
		if err != nil {
			t.Fatal(err)
		}
		mats[id] = m
		presetIDs = append(presetIDs, id)
	}
	t.Logf("preset %d keys done", preset)

	// Capture the pre-rotation master key (the "attacker's" bytes).
	v.mu.RLock()
	oldMaster := v.cur.key
	v.mu.RUnlock()

	var stop atomic.Bool
	var wg sync.WaitGroup
	fail := func(format string, args ...any) { t.Errorf(format, args...) }

	// Readers: random live-key reads must always return correct bytes.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				id := presetIDs[rng.Intn(len(presetIDs))]
				got, err := v.GetMaterial(id)
				if err == ErrKeyNotFound {
					continue
				}
				if err != nil {
					fail("GetMaterial(%s): %v", id, err)
					return
				}
				matsMu.RLock()
				want := mats[id]
				matsMu.RUnlock()
				if !bytes.Equal(got, want) {
					fail("GetMaterial(%s) returned wrong bytes", id)
					return
				}
			}
		}(int64(w))
	}

	// Creators: new keys made during the rotation must stay readable.
	var extraMu sync.Mutex
	var extraIDs []string
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				id, err := v.CreateKey()
				if err != nil {
					fail("CreateKey: %v", err)
					return
				}
				m, err := v.GetMaterial(id)
				if err != nil {
					fail("GetMaterial(new %s): %v", id, err)
					return
				}
				matsMu.Lock()
				mats[id] = m
				matsMu.Unlock()
				extraMu.Lock()
				extraIDs = append(extraIDs, id)
				extraMu.Unlock()
			}
		}()
	}

	// Destroyer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		rng := rand.New(rand.NewSource(99))
		i := 0
		for !stop.Load() {
			id := presetIDs[rng.Intn(len(presetIDs))]
			if err := v.DestroyKey(id); err != nil {
				fail("DestroyKey(%s): %v", id, err)
				return
			}
			matsMu.Lock()
			if m, ok := mats[id]; ok {
				destroyed[id] = m
			}
			matsMu.Unlock()
			i++
		}
	}()

	rotErr := v.RotateMaster("new-passphrase")
	stop.Store(true)
	wg.Wait()
	if rotErr != nil {
		t.Fatalf("RotateMaster: %v", rotErr)
	}
	if t.Failed() {
		return
	}
	extraMu.Lock()
	t.Logf("rotation done; %d keys created and some destroyed during rotation", len(extraIDs))
	extraMu.Unlock()

	// Capture the current (post-rotation) master key.
	v.mu.RLock()
	newMaster := v.cur.key
	v.mu.RUnlock()
	if newMaster == oldMaster {
		t.Fatal("master key did not change")
	}

	oldGCM, err := cipher.NewGCM(must(aes.NewCipher(oldMaster[:])))
	if err != nil {
		t.Fatal(err)
	}
	newGCM, err := cipher.NewGCM(must(aes.NewCipher(newMaster[:])))
	if err != nil {
		t.Fatal(err)
	}

	destroyedMats := make(map[[32]byte]bool)
	matsMu.RLock()
	for _, m := range destroyed {
		destroyedMats[[32]byte(m)] = true
	}
	matsMu.RUnlock()

	rows, err := v.db.Query(`SELECT id,gen,nonce,ct FROM keys`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var id string
		var gen int64
		var nonce, ct []byte
		if err := rows.Scan(&id, &gen, &nonce, &ct); err != nil {
			t.Fatal(err)
		}
		seen++
		// 1. old master key must not open any ciphertext
		if _, err := oldGCM.Open(nil, nonce, ct, nil); err == nil {
			t.Fatalf("ciphertext of %s decrypts with OLD master key", id)
		}
		// 2. current master key must open it
		plain, err := newGCM.Open(nil, nonce, ct, nil)
		if err != nil {
			t.Fatalf("ciphertext of %s does not decrypt with current master key: %v", id, err)
		}
		// 3. it must be a live key with the right bytes
		matsMu.RLock()
		want, ok := mats[id]
		_, isDestroyed := destroyed[id]
		matsMu.RUnlock()
		if !ok || isDestroyed {
			t.Fatalf("destroyed/unknown key %s still present in DB", id)
		}
		if !bytes.Equal(plain, want) {
			t.Fatalf("DB material of %s does not match expected bytes", id)
		}
		// 4. no destroyed key's material may reappear
		if destroyedMats[[32]byte(plain)] {
			t.Fatalf("material of destroyed key reappears in DB (id %s)", id)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	matsMu.RLock()
	live := len(mats) - len(destroyed)
	matsMu.RUnlock()
	if seen != live {
		t.Fatalf("DB has %d rows, expected %d live keys", seen, live)
	}
	t.Logf("verified %d ciphertexts: none open with old key, all correct with current key", seen)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

var _ = fmt.Sprintf // keep fmt import if unused in future edits
