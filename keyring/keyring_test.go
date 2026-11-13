package keyring

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/adrg/xdg"
)

func setup(t *testing.T) {
	t.Helper()
	oldDataHome := xdg.DataHome
	t.Cleanup(func() { xdg.DataHome = oldDataHome })
	xdg.DataHome = t.TempDir()
}

func TestGenerate_InvalidName(t *testing.T) {
	setup(t)
	for _, name := range []string{".", "..", "../escaped", "nested/key", `nested\key`, "/absolute"} {
		t.Run(name, func(t *testing.T) {
			if _, err := Generate(name); err == nil {
				t.Fatalf("accepted invalid name %q", name)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(xdg.DataHome, "cryptree", "escaped.key")); !os.IsNotExist(err) {
		t.Fatalf("unexpected escaped key: %v", err)
	}
}

func TestGenerate_DanglingSymlink(t *testing.T) {
	setup(t)
	dir, err := KeysDir()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(target, filepath.Join(dir, "linked.key")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Generate("linked"); err == nil {
		t.Fatal("expected existing symlink to be rejected")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("symlink target was created: %v", err)
	}
}

func TestGenerate_ConcurrentSameName(t *testing.T) {
	setup(t)
	const count = 16
	results := make(chan *age.X25519Identity, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			<-start
			id, err := Generate("shared")
			if err == nil {
				results <- id
			}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatalf("want one successful creation, got %d", len(results))
	}
	winner := <-results
	keys, err := PublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != winner.Recipient().String() {
		t.Fatalf("stored key does not match successful creation: %v", keys)
	}
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
