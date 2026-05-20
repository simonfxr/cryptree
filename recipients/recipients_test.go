package recipients

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)
	os.WriteFile(p, []byte("# comment\n\nkey1\n  key2  \n# another\nkey3\n"), 0644)

	keys, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"key1", "key2", "key3"}
	if len(keys) != len(want) {
		t.Fatalf("got %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("keys[%d] = %q, want %q", i, keys[i], want[i])
		}
	}
}

func TestResolveWalksUp(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, FileName), []byte("parentkey\n"), 0644)
	child := filepath.Join(dir, "a", "b")
	os.MkdirAll(child, 0755)

	keys, err := Resolve(filepath.Join(child, "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "parentkey" {
		t.Fatalf("got %v, want [parentkey]", keys)
	}
}

func TestResolveNoMarker(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	os.MkdirAll(deep, 0755)

	_, err := Resolve(filepath.Join(deep, "file.txt"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestResolveDirChecksItself(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, FileName), []byte("dirkey\n"), 0644)

	keys, err := ResolveDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "dirkey" {
		t.Fatalf("got %v, want [dirkey]", keys)
	}
}

func TestAppendCreatesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)

	if err := Append(p, "newkey"); err != nil {
		t.Fatal(err)
	}
	keys, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "newkey" {
		t.Fatalf("got %v, want [newkey]", keys)
	}
}

func TestAppendToExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)
	os.WriteFile(p, []byte("existing\n"), 0644)

	if err := Append(p, "added"); err != nil {
		t.Fatal(err)
	}
	keys, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "existing" || keys[1] != "added" {
		t.Fatalf("got %v, want [existing added]", keys)
	}
}

func TestChildOverridesParent(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, FileName), []byte("parentkey\n"), 0644)
	child := filepath.Join(dir, "sub")
	os.MkdirAll(child, 0755)
	os.WriteFile(filepath.Join(child, FileName), []byte("childkey\n"), 0644)

	keys, err := Resolve(filepath.Join(child, "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "childkey" {
		t.Fatalf("got %v, want [childkey]", keys)
	}
}
