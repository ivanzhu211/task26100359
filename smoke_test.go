package keyvault

import (
	"bytes"
	"testing"
)

func TestSmokeOpenCreateGetDestroy(t *testing.T) {
	path := t.TempDir() + "/v.db"
	v, err := Open(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	id, err := v.CreateKey()
	if err != nil {
		t.Fatal(err)
	}
	m1, err := v.GetMaterial(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(m1) != keyMaterialLen {
		t.Fatalf("bad material len %d", len(m1))
	}
	if err := v.DestroyKey(id); err != nil {
		t.Fatal(err)
	}
	if _, err := v.GetMaterial(id); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if _, err := Open(path, "wrong"); err != ErrBadPassphrase {
		t.Fatalf("expected ErrBadPassphrase, got %v", err)
	}
}

func TestSmokeRotate(t *testing.T) {
	path := t.TempDir() + "/v.db"
	v, err := Open(path, "old-pw")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, 2000)
	mats := make(map[string][]byte)
	for i := 0; i < 2000; i++ {
		id, err := v.CreateKey()
		if err != nil {
			t.Fatal(err)
		}
		m, err := v.GetMaterial(id)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		mats[id] = m
	}
	// destroy some
	for i := 0; i < 100; i++ {
		if err := v.DestroyKey(ids[i]); err != nil {
			t.Fatal(err)
		}
		delete(mats, ids[i])
	}
	if err := v.RotateMaster("new-pw"); err != nil {
		t.Fatal(err)
	}
	for id, want := range mats {
		got, err := v.GetMaterial(id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("material mismatch for %s", id)
		}
	}
	v.Close()

	if _, err := Open(path, "old-pw"); err != ErrBadPassphrase {
		t.Fatalf("old passphrase must fail, got %v", err)
	}
	v2, err := Open(path, "new-pw")
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	for id, want := range mats {
		got, err := v2.GetMaterial(id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("material mismatch after reopen for %s", id)
		}
	}
}
