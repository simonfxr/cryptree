package format

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func genKey(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEncryptDecryptSingleRecipient(t *testing.T) {
	id := genKey(t)
	plain := []byte("hello world")
	payload, err := Encrypt(plain, []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(payload, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q, want %q", got, plain)
	}
}

func TestEncryptDecryptMultipleRecipients(t *testing.T) {
	ids := []*age.X25519Identity{genKey(t), genKey(t), genKey(t)}
	rcpts := make([]string, len(ids))
	for i, id := range ids {
		rcpts[i] = id.Recipient().String()
	}
	plain := []byte("multi-recipient secret")
	payload, err := Encrypt(plain, rcpts)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		got, err := Decrypt(payload, []age.Identity{id})
		if err != nil {
			t.Fatalf("recipient %d: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("recipient %d: got %q, want %q", i, got, plain)
		}
	}
}

func TestDecryptWrongKey(t *testing.T) {
	id := genKey(t)
	wrong := genKey(t)
	payload, err := Encrypt([]byte("secret"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decrypt(payload, []age.Identity{wrong})
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestEncryptInvalidRecipient(t *testing.T) {
	_, err := Encrypt([]byte("x"), []string{"not-a-valid-recipient"})
	if err == nil {
		t.Fatal("expected error for invalid recipient")
	}
}

func TestDecodeEncodeRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second).UTC()
	sf := &SecretFile{
		Version:    1,
		Recipients: []string{"age1abc", "age1def"},
		Attributes: map[string]string{"env": "prod", "app": "web"},
		Created:    now,
		Modified:   now,
		Payload:    "dGVzdA==\n",
	}
	var buf bytes.Buffer
	if err := Encode(&buf, sf); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != sf.Version {
		t.Fatalf("version: got %d, want %d", got.Version, sf.Version)
	}
	if len(got.Recipients) != len(sf.Recipients) {
		t.Fatalf("recipients length mismatch")
	}
	for i := range sf.Recipients {
		if got.Recipients[i] != sf.Recipients[i] {
			t.Fatalf("recipient %d: got %q, want %q", i, got.Recipients[i], sf.Recipients[i])
		}
	}
	if got.Attributes["env"] != "prod" || got.Attributes["app"] != "web" {
		t.Fatalf("attributes mismatch: %v", got.Attributes)
	}
	if !got.Created.Equal(sf.Created) || !got.Modified.Equal(sf.Modified) {
		t.Fatalf("time mismatch")
	}
	if got.Payload != sf.Payload {
		t.Fatalf("payload: got %q, want %q", got.Payload, sf.Payload)
	}
}

func TestPayloadIsMultiLine(t *testing.T) {
	id := genKey(t)
	// Use enough data to produce >76 chars of base64
	plain := bytes.Repeat([]byte("A"), 200)
	payload, err := Encrypt(plain, []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(payload, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected multi-line payload, got %d lines", len(lines))
	}
	for i, line := range lines {
		if len(line) > 76 {
			t.Fatalf("line %d exceeds 76 chars: %d", i, len(line))
		}
	}
}

func TestBinaryDataRoundTrip(t *testing.T) {
	id := genKey(t)
	plain := make([]byte, 256)
	for i := range plain {
		plain[i] = byte(i)
	}
	payload, err := Encrypt(plain, []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(payload, []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("binary round-trip mismatch")
	}
}
