package vault

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCrashRecovery repeatedly runs RotateMaster in a child process and kills
// it with SIGKILL at random points. After every round the next child recovers
// via Open (new passphrase first, then old) and re-rotates; some of those
// follow-up rotations are killed again. After all rounds the parent verifies
// every surviving key byte-for-byte.
func TestCrashRecovery(t *testing.T) {
	if os.Getenv("VAULT_CRASH_CHILD") == "1" {
		return // we are the child; the real test is TestCrashChild
	}
	dir := t.TempDir()
	db := filepath.Join(dir, "v.db")
	manifestPath := filepath.Join(dir, "manifest.txt")
	logPath := filepath.Join(dir, "child.log")

	const nKeys = 20000
	v, err := Open(db, "pass-A")
	if err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	for i := 0; i < nKeys; i++ {
		id, err := v.CreateKey()
		if err != nil {
			t.Fatal(err)
		}
		m, err := v.GetMaterial(id)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%s %s\n", id, hex.EncodeToString(m))
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte(manifest.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("manifest: %d keys", nKeys)

	cur, other := "pass-A", "pass-B"
	// Kill strategies per round, chosen to cover: kill during Open/recovery,
	// kill right after recovery during the fresh rotation, kill late in the
	// rotation, and kill after the rotation fully completed.
	strategies := []int{1, 2, 1, 0, 3, 1, 2, 0, 1, 3, 1, 2, 1, 0}
	interrupted, completed := 0, 0
	rng := rand.New(rand.NewSource(42))

	for round, strategy := range strategies {
		os.WriteFile(logPath, nil, 0o644)
		cmd := exec.Command(os.Args[0], "-test.run=TestCrashChild")
		cmd.Env = append(os.Environ(),
			"VAULT_CRASH_CHILD=1",
			"VAULT_CRASH_DB="+db,
			"VAULT_CRASH_MANIFEST="+manifestPath,
			"VAULT_CRASH_LOG="+logPath,
			"VAULT_CRASH_OLD="+cur,
			"VAULT_CRASH_NEW="+other,
		)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		switch strategy {
		case 0: // kill at a random time, possibly before Open finishes
			time.Sleep(time.Duration(rng.Intn(1500)) * time.Millisecond)
		case 1: // kill right after recovery, during the fresh rotation
			waitMarker(t, logPath, "rotating", 60*time.Second)
			time.Sleep(time.Duration(rng.Intn(120)) * time.Millisecond)
		case 2: // kill later in the rotation
			waitMarker(t, logPath, "rotating", 60*time.Second)
			time.Sleep(time.Duration(rng.Intn(900)) * time.Millisecond)
		case 3: // let the rotation finish, then kill
			waitMarker(t, logPath, "rotated", 90*time.Second)
			time.Sleep(time.Duration(rng.Intn(200)) * time.Millisecond)
		}
		cmd.Process.Kill()
		cmd.Wait()

		logBytes, _ := os.ReadFile(logPath)
		log := string(logBytes)
		if strings.Contains(log, "FAIL") {
			t.Fatalf("round %d: child reported failure:\n%s", round, log)
		}
		switch {
		case strings.Contains(log, "rotated"):
			completed++
		case strings.Contains(log, "rotating"):
			interrupted++
		}
		cur, other = other, cur
	}
	t.Logf("rounds done: %d interrupted rotations, %d completed rotations", interrupted, completed)
	if interrupted < 3 {
		t.Fatalf("too few interrupted rotations: %d", interrupted)
	}
	if completed < 1 {
		t.Fatalf("no completed rotation round")
	}

	// Final recovery, caller order: last rotation's new passphrase first.
	v2, err := Open(db, other)
	if err != nil {
		v2, err = Open(db, cur)
		if err != nil {
			t.Fatal("neither passphrase opens the vault")
		}
	}
	// Exactly one passphrase must be valid now.
	if _, err := Open(db, "pass-neither"); err == nil {
		t.Fatal("unknown passphrase accepted")
	}
	good := 0
	for _, p := range []string{cur, other} {
		if vv, err := Open(db, p); err == nil {
			good++
			vv.Close()
		}
	}
	if good != 1 {
		t.Fatalf("expected exactly 1 valid passphrase, got %d", good)
	}
	// Byte-for-byte check of every surviving key.
	for _, line := range strings.Split(strings.TrimSpace(manifest.String()), "\n") {
		parts := strings.Fields(line)
		want, _ := hex.DecodeString(parts[1])
		got, err := v2.GetMaterial(parts[0])
		if err != nil {
			t.Fatalf("GetMaterial(%s) after crashes: %v", parts[0], err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("key %s material mismatch after crashes", parts[0])
		}
	}
	v2.Close()
	t.Logf("all %d keys verified byte-for-byte after crash rounds", nKeys)
}

// TestCrashChild is the helper process: recover, verify, rotate, then wait
// to be killed.
func TestCrashChild(t *testing.T) {
	if os.Getenv("VAULT_CRASH_CHILD") != "1" {
		t.Skip("helper process")
	}
	db := os.Getenv("VAULT_CRASH_DB")
	manifestPath := os.Getenv("VAULT_CRASH_MANIFEST")
	logPath := os.Getenv("VAULT_CRASH_LOG")
	oldPass := os.Getenv("VAULT_CRASH_OLD")
	newPass := os.Getenv("VAULT_CRASH_NEW")

	logf := func(format string, args ...any) {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			os.Exit(1)
		}
		fmt.Fprintf(f, format+"\n", args...)
		f.Close()
	}
	fail := func(format string, args ...any) {
		logf("FAIL "+format, args...)
		os.Exit(1)
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		fail("read manifest: %v", err)
	}

	// Caller does not know how far the rotation got: new first, then old.
	v, err := Open(db, newPass)
	openedWith := newPass
	if err != nil {
		v, err = Open(db, oldPass)
		openedWith = oldPass
	}
	if err != nil {
		fail("open: %v", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(manifestBytes)), "\n") {
		parts := strings.Fields(line)
		want, _ := hex.DecodeString(parts[1])
		got, err := v.GetMaterial(parts[0])
		if err != nil {
			fail("verify %s: %v", parts[0], err)
		}
		if !bytes.Equal(got, want) {
			fail("verify %s: wrong bytes", parts[0])
		}
	}
	logf("verified")

	target := oldPass
	if openedWith == oldPass {
		target = newPass
	}
	logf("rotating")
	if err := v.RotateMaster(target); err != nil {
		fail("rotate: %v", err)
	}
	logf("rotated")
	time.Sleep(60 * time.Second) // parent will SIGKILL us
}

func waitMarker(t *testing.T, logPath, marker string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(logPath); err == nil && strings.Contains(string(b), marker) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("timeout waiting for marker %q; child log:\n%s", marker, string(b))
}
