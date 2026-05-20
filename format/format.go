package format

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

type SecretFile struct {
	Version    int               `yaml:"version"`
	Recipients []string          `yaml:"recipients"`
	Attributes map[string]string `yaml:"attributes,omitempty"`
	Created    time.Time         `yaml:"created"`
	Modified   time.Time         `yaml:"modified"`
	Payload    string            `yaml:"payload"`
}

func Encode(w io.Writer, sf *SecretFile) error {
	enc := yaml.NewEncoder(w)
	defer enc.Close()
	return enc.Encode(sf)
}

func Decode(r io.Reader) (*SecretFile, error) {
	var sf SecretFile
	if err := yaml.NewDecoder(r).Decode(&sf); err != nil {
		return nil, err
	}
	return &sf, nil
}

func Encrypt(plaintext []byte, recipients []string) (string, error) {
	rcpts := make([]age.Recipient, len(recipients))
	for i, s := range recipients {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return "", err
		}
		rcpts[i] = r
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpts...)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	var wrapped strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := min(i+76, len(encoded))
		wrapped.WriteString(encoded[i:end])
		wrapped.WriteByte('\n')
	}
	return wrapped.String(), nil
}

func Decrypt(payload string, identities []age.Identity) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload, "\n", ""))
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}
