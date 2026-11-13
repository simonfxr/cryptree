package keyring

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/adrg/xdg"
)

func KeysDir() (string, error) {
	dir := filepath.Join(xdg.DataHome, "cryptree", "keys")
	return dir, os.MkdirAll(dir, 0700)
}

func Generate(name string) (*age.X25519Identity, error) {
	if name != "" && (!filepath.IsLocal(name) || name == "." || strings.ContainsAny(name, `/\`)) {
		return nil, fmt.Errorf("invalid key name %q: must be a filename, not a path", name)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	if name == "" {
		pub := id.Recipient().String()
		name = pub[4:20]
	}
	dir, err := KeysDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name+".key")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return nil, fmt.Errorf("key %q already exists", name)
	}
	if err != nil {
		return nil, err
	}
	data := fmt.Sprintf("# public key: %s\n%s\n", id.Recipient(), id)
	_, writeErr := f.WriteString(data)
	closeErr := f.Close()
	if writeErr != nil {
		os.Remove(path)
		return nil, writeErr
	}
	if closeErr != nil {
		os.Remove(path)
		return nil, closeErr
	}
	return id, nil
}

func LoadAll() ([]age.Identity, error) {
	dir, err := KeysDir()
	if err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.key"))
	if err != nil {
		return nil, err
	}
	var ids []age.Identity
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		parsed, err := age.ParseIdentities(strings.NewReader(string(data)))
		if err != nil {
			return nil, err
		}
		ids = append(ids, parsed...)
	}
	return ids, nil
}

func PublicKeys() ([]string, error) {
	ids, err := LoadAll()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			keys = append(keys, x.Recipient().String())
		}
	}
	return keys, nil
}
