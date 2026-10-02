package keyvault

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestCrashRecovery kills a child process with SIGKILL at random points
// during RotateMaster, then recovers by trying the new passphrase first and
// the old one second. Exactly one must work, and every live key must read
// back byte-exact. Rounds are chained: immediately after recovery a new
// rotation is started and killed again.
func TestCrashRecovery(t *testing.T) {
	if os.Getenv("KV_CRASH_CHILD") == "1" {
		runCrashChild(t)
		return
	}
	if testing.Short() {
		t.Skip("crash test disabled in -short mode")
	}

	const (
		outerRounds = 3
		seedCount   = 10000
	)
	// Chained kill scenarios per vault: immediately after recovery the next
	// rotation is started and killed again. Timings are chosen to land in
	// every crash window.
	scenarios := []struct {
		slowBatchMS        int // test hook: pause between rotation batches
		sleepMin, sleepMax int
	}{
		{0, 0, 100},      // killed before the meta commit
		{30, 400, 1200},  // killed mid-batches
		{30, 3000, 4000}, // killed after the rotation completed
		{0, 0, 1500},     // random moment
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var oldRecoveries, newRecoveries int

	for round := 0; round < outerRounds; round++ {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "v.db")
		manifestPath := filepath.Join(dir, "manifest.txt")

		// Seed a fresh vault in-process.
		seedPW := fmt.Sprintf("pw-r%d-seed", round)
		v, err := Open(dbPath, seedPW)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		for id, m := range seedKeys(t, v, seedCount) {
			fmt.Fprintf(manifest, "C %s %x\n", id, m)
		}
		manifest.Close()
		v.Close()

		cur := seedPW
		for kill, sc := range scenarios {
			next := fmt.Sprintf("pw-r%d-k%d", round, kill)

			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashRecovery$", "-test.v")
			cmd.Env = append(os.Environ(),
				"KV_CRASH_CHILD=1",
				"KV_DB="+dbPath,
				"KV_CUR="+cur,
				"KV_NEW="+next,
				"KV_MANIFEST="+manifestPath,
				fmt.Sprintf("KV_SLOW_BATCH_MS=%d", sc.slowBatchMS),
			)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			// Kill at a random moment inside the scenario's window.
			delta := sc.sleepMax - sc.sleepMin
			sleep := sc.sleepMin
			if delta > 0 {
				sleep += rng.Intn(delta)
			}
			time.Sleep(time.Duration(sleep) * time.Millisecond)
			cmd.Process.Kill()
			cmd.Wait()

			live := replayManifest(t, manifestPath)
			worked := recoverAndVerify(t, dbPath, next, cur, live)
			which := "old"
			if worked == next {
				which = "new"
				newRecoveries++
			} else {
				oldRecoveries++
			}
			t.Logf("round %d kill %d (scenario %d): recovered with %s passphrase (%d live keys)",
				round, kill, kill, which, len(live))
			cur = worked
		}
	}
	if oldRecoveries == 0 || newRecoveries == 0 {
		t.Fatalf("crash windows not covered: old-passphrase recoveries=%d, new-passphrase recoveries=%d",
			oldRecoveries, newRecoveries)
	}
}

// runCrashChild is the child-process body: open the vault, rotate the
// master key while creating keys, then wait to be killed.
func runCrashChild(t *testing.T) {
	dbPath := os.Getenv("KV_DB")
	cur := os.Getenv("KV_CUR")
	next := os.Getenv("KV_NEW")
	manifestPath := os.Getenv("KV_MANIFEST")

	if ms, _ := strconv.Atoi(os.Getenv("KV_SLOW_BATCH_MS")); ms > 0 {
		rotateBatchPause = time.Duration(ms) * time.Millisecond
	}

	v, err := Open(dbPath, cur)
	if err != nil {
		fmt.Fprintf(os.Stderr, "child: open: %v\n", err)
		os.Exit(2)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		f, err := os.OpenFile(manifestPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		defer f.Close()
		for {
			select {
			case <-stop:
				return
			default:
			}
			id, err := v.CreateKey()
			if err != nil {
				return
			}
			m, err := v.GetMaterial(id)
			if err != nil {
				return
			}
			fmt.Fprintf(f, "C %s %x\n", id, m)
			f.Sync()
		}
	}()

	if err := v.RotateMaster(next); err != nil {
		fmt.Fprintf(os.Stderr, "child: rotate: %v\n", err)
		os.Exit(2)
	}
	close(stop)
	<-done
	// Rotation finished; wait to be killed by the parent.
	time.Sleep(time.Hour)
}

// replayManifest folds the create-log into the set of live id -> material.
func replayManifest(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	live := make(map[string][]byte)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var op, id, hexMat string
		if _, err := fmt.Sscanf(sc.Text(), "%s %s %s", &op, &id, &hexMat); err != nil {
			t.Fatalf("bad manifest line %q: %v", sc.Text(), err)
		}
		m, err := hex.DecodeString(hexMat)
		if err != nil {
			t.Fatal(err)
		}
		switch op {
		case "C":
			live[id] = m
		case "D":
			delete(live, id)
		}
	}
	return live
}

// recoverAndVerify opens the vault trying newPW first then oldPW, verifies
// every live key byte-exact, and verifies the other passphrase is invalid.
// It returns the passphrase that worked.
func recoverAndVerify(t *testing.T, dbPath, newPW, oldPW string, live map[string][]byte) string {
	t.Helper()
	v, err := Open(dbPath, newPW)
	worked := newPW
	if err != nil {
		if err != ErrBadPassphrase {
			t.Fatalf("Open with new passphrase failed unexpectedly: %v", err)
		}
		v, err = Open(dbPath, oldPW)
		if err != nil {
			t.Fatalf("both passphrases failed; old: %v", err)
		}
		worked = oldPW
	}
	defer v.Close()

	for id, want := range live {
		got, err := v.GetMaterial(id)
		if err != nil {
			t.Fatalf("live key %s unreadable after recovery: %v", id, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("live key %s has wrong bytes after recovery", id)
		}
	}

	other := oldPW
	if worked == oldPW {
		other = newPW
	}
	v2, err := Open(dbPath, other)
	if err != ErrBadPassphrase {
		if v2 != nil {
			v2.Close()
		}
		t.Fatalf("passphrase %q must be invalid after recovery, got err=%v", other, err)
	}
	return worked
}
