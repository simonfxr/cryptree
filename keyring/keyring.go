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
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("key %q already exists", name)
	}
	data := fmt.Sprintf("# public key: %s\n%s\n", id.Recipient(), id)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		return nil, err
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
