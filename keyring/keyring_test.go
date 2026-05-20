package keyring

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/adrg/xdg"
)

func setup(t *testing.T) {
	t.Helper()
	xdg.DataHome = t.TempDir()
}

func TestGenerate_CustomName(t *testing.T) {
	setup(t)
	id, err := Generate("mykey")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := KeysDir()
	path := filepath.Join(dir, "mykey.key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("want 0600, got %o", perm)
	}
	if id.Recipient().String() == "" {
		t.Fatal("expected non-empty public key")
	}
}

func TestGenerate_EmptyName(t *testing.T) {
	setup(t)
	id, err := Generate("")
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Recipient().String()
	expectedName := pub[4:20]
	dir, _ := KeysDir()
	path := filepath.Join(dir, expectedName+".key")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file %s to exist: %v", path, err)
	}
}

func TestGenerate_DuplicateName(t *testing.T) {
	setup(t)
	if _, err := Generate("dup"); err != nil {
		t.Fatal(err)
	}
	_, err := Generate("dup")
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestLoadAll(t *testing.T) {
	setup(t)
	id1, _ := Generate("k1")
	id2, _ := Generate("k2")
	ids, err := LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("want 2 identities, got %d", len(ids))
	}
	pubs := map[string]bool{
		id1.Recipient().String(): true,
		id2.Recipient().String(): true,
	}
	for _, id := range ids {
		x := id.(*age.X25519Identity)
		if !pubs[x.Recipient().String()] {
			t.Fatalf("unexpected key %s", x.Recipient())
		}
	}
}

func TestPublicKeys(t *testing.T) {
	setup(t)
	id, _ := Generate("pk")
	keys, err := PublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != id.Recipient().String() {
		t.Fatalf("want [%s], got %v", id.Recipient(), keys)
	}
}

func TestKeysDir_Permissions(t *testing.T) {
	setup(t)
	dir, err := KeysDir()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Fatalf("want 0700, got %o", perm)
	}
}
