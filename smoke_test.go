package vault

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestSmoke(t *testing.T) {
	db := filepath.Join(t.TempDir(), "v.db")
	v, err := Open(db, "pw1")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 50)
	mats := make(map[string][]byte)
	for i := range ids {
		id, err := v.CreateKey()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
		m, err := v.GetMaterial(id)
		if err != nil {
			t.Fatal(err)
		}
		if len(m) != 32 {
			t.Fatalf("bad material len %d", len(m))
		}
		mats[id] = m
	}
	if err := v.DestroyKey(ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := v.GetMaterial(ids[0]); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if err := v.RotateMaster("pw2"); err != nil {
		t.Fatal(err)
	}
	for id, want := range mats {
		got, err := v.GetMaterial(id)
		if id == ids[0] {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("material mismatch for %s", id)
		}
	}
	v.Close()

	// old passphrase must fail, new must work
	if _, err := Open(db, "pw1"); err == nil {
		t.Fatal("old passphrase still works after rotation")
	}
	v2, err := Open(db, "pw2")
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range mats {
		if id == ids[0] {
			continue
		}
		got, err := v2.GetMaterial(id)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("after reopen: mismatch for %s err=%v", id, err)
		}
	}
	v2.Close()

	// wrong passphrase on fresh vault path
	if _, err := Open(db, "nope"); err == nil {
		t.Fatal("bad passphrase accepted")
	}
}
