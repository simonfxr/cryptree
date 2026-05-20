package main

import (
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/simonfxr/cryptree/format"
	"github.com/simonfxr/cryptree/keyring"
	"github.com/simonfxr/cryptree/recipients"
)

type KeygenCmd struct {
	Name         string `arg:"--name" help:"label for the key"`
	AddRecipient bool   `arg:"--add-recipient" help:"append public key to nearest .cryptree_recipients"`
	ReEncrypt    bool   `arg:"--re-encrypt" help:"re-encrypt tree after keygen"`
}

type EncryptCmd struct {
	Path    string   `arg:"positional,required" help:"output .yaml file path"`
	Attr    []string `arg:"--attr,separate" help:"key=value attribute (empty value removes key)"`
	Replace bool     `arg:"--replace" help:"replace existing file completely"`
	Update  bool     `arg:"--update" help:"update payload, preserve created timestamp and merge attributes"`
}

type DecryptCmd struct {
	Path string `arg:"positional,required" help:".yaml secret file to decrypt"`
}

type ReEncryptCmd struct {
	DryRun bool     `arg:"--dry-run" help:"print files that would change"`
	Force  bool     `arg:"--force" help:"re-encrypt even if recipients match"`
	Paths  []string `arg:"positional,required"`
}

type args struct {
	Keygen    *KeygenCmd    `arg:"subcommand:keygen" help:"generate a new age keypair"`
	Encrypt   *EncryptCmd   `arg:"subcommand:encrypt" help:"encrypt stdin to a secret file"`
	Decrypt   *DecryptCmd   `arg:"subcommand:decrypt" help:"decrypt a secret file to stdout"`
	ReEncrypt *ReEncryptCmd `arg:"subcommand:re-encrypt" help:"re-encrypt secrets with current recipients"`
}

func (args) Description() string {
	return "Age-encrypted secret store with hierarchical recipient management."
}

func fatal(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func main() {
	var a args
	p := arg.MustParse(&a)
	if p.Subcommand() == nil {
		p.WriteUsage(os.Stderr)
		os.Exit(1)
	}
	switch {
	case a.Keygen != nil:
		runKeygen(a.Keygen)
	case a.Encrypt != nil:
		runEncrypt(a.Encrypt)
	case a.Decrypt != nil:
		runDecrypt(a.Decrypt)
	case a.ReEncrypt != nil:
		runReEncrypt(a.ReEncrypt)
	}
}

func runKeygen(cmd *KeygenCmd) {
	id, err := keyring.Generate(cmd.Name)
	if err != nil {
		fatal("keygen: %v", err)
	}
	pubkey := id.Recipient().String()
	fmt.Println(pubkey)

	if cmd.AddRecipient {
		cwd, err := os.Getwd()
		if err != nil {
			fatal("keygen: %v", err)
		}
		rFile, err := findRecipientsFile(cwd)
		if err != nil {
			fatal("keygen: %v", err)
		}
		if err := recipients.Append(rFile, pubkey); err != nil {
			fatal("keygen: %v", err)
		}
	}

	if cmd.ReEncrypt {
		cwd, err := os.Getwd()
		if err != nil {
			fatal("keygen: %v", err)
		}
		root, err := findTreeRoot(cwd)
		if err != nil {
			fatal("keygen: %v", err)
		}
		reEncryptDir(root, false, true)
	}
}

func runEncrypt(cmd *EncryptCmd) {
	if !strings.HasSuffix(cmd.Path, ".yaml") {
		fatal("encrypt: path must end in .yaml")
	}
	plaintext, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("encrypt: %v", err)
	}
	rcpts, err := recipients.Resolve(cmd.Path)
	if err != nil {
		fatal("encrypt: %v", err)
	}

	now := time.Now().UTC()
	var sf format.SecretFile
	sf.Version = 1
	sf.Recipients = rcpts
	sf.Created = now
	sf.Modified = now
	sf.Attributes = make(map[string]string)

	_, statErr := os.Stat(cmd.Path)
	if statErr == nil {
		if !cmd.Replace && !cmd.Update {
			fatal("encrypt: file exists; use --replace or --update")
		}
		if cmd.Update {
			existing, err := readSecretFile(cmd.Path)
			if err != nil {
				fatal("encrypt: %v", err)
			}
			sf.Created = existing.Created
			maps.Copy(sf.Attributes, existing.Attributes)
		}
	} else if !os.IsNotExist(statErr) {
		fatal("encrypt: %v", statErr)
	}

	for _, a := range cmd.Attr {
		k, v, found := strings.Cut(a, "=")
		if !found {
			fatal("encrypt: invalid --attr %q (expected key=value)", a)
		}
		if v == "" {
			delete(sf.Attributes, k)
		} else {
			sf.Attributes[k] = v
		}
	}
	if len(sf.Attributes) == 0 {
		sf.Attributes = nil
	}

	payload, err := format.Encrypt(plaintext, rcpts)
	if err != nil {
		fatal("encrypt: %v", err)
	}
	sf.Payload = payload

	f, err := os.Create(cmd.Path)
	if err != nil {
		fatal("encrypt: %v", err)
	}
	defer f.Close()
	if err := format.Encode(f, &sf); err != nil {
		fatal("encrypt: %v", err)
	}
}

func runDecrypt(cmd *DecryptCmd) {
	sf, err := readSecretFile(cmd.Path)
	if err != nil {
		fatal("decrypt: %v", err)
	}
	ids, err := keyring.LoadAll()
	if err != nil {
		fatal("decrypt: %v", err)
	}
	plaintext, err := format.Decrypt(sf.Payload, ids)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt: %v\n", err)
		os.Exit(2)
	}
	os.Stdout.Write(plaintext)
}

func runReEncrypt(cmd *ReEncryptCmd) {
	for _, p := range cmd.Paths {
		info, err := os.Stat(p)
		if err != nil {
			fatal("re-encrypt: %v", err)
		}
		if info.IsDir() {
			reEncryptDir(p, cmd.DryRun, cmd.Force)
		} else {
			reEncryptFile(p, cmd.DryRun, cmd.Force)
		}
	}
}

func reEncryptDir(dir string, dryRun, force bool) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "re-encrypt: %s: %v\n", path, err)
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, ".yaml") {
			reEncryptFile(path, dryRun, force)
		}
		return nil
	})
}

func reEncryptFile(path string, dryRun, force bool) {
	sf, err := readSecretFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "re-encrypt: skipping %s: %v\n", path, err)
		return
	}
	if sf.Version == 0 || sf.Payload == "" {
		return
	}
	rcpts, err := recipients.Resolve(path)
	if err != nil {
		fatal("re-encrypt: %v", err)
	}

	if !force && recipientsEqual(sf.Recipients, rcpts) {
		return
	}

	if dryRun {
		fmt.Println(path)
		return
	}

	ids, err := keyring.LoadAll()
	if err != nil {
		fatal("re-encrypt: %v", err)
	}
	plaintext, err := format.Decrypt(sf.Payload, ids)
	if err != nil {
		fmt.Fprintf(os.Stderr, "re-encrypt: %s: %v\n", path, err)
		os.Exit(2)
	}

	payload, err := format.Encrypt(plaintext, rcpts)
	if err != nil {
		fatal("re-encrypt: %v", err)
	}
	sf.Recipients = rcpts
	sf.Payload = payload
	sf.Modified = time.Now().UTC()

	f, err := os.Create(path)
	if err != nil {
		fatal("re-encrypt: %v", err)
	}
	defer f.Close()
	if err := format.Encode(f, sf); err != nil {
		fatal("re-encrypt: %v", err)
	}
}

func readSecretFile(path string) (*format.SecretFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return format.Decode(f)
}

func recipientsEqual(a, b []string) bool {
	x := slices.Clone(a)
	y := slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

func findRecipientsFile(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, recipients.FileName)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no %s found", recipients.FileName)
		}
		dir = parent
	}
}

func findTreeRoot(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, recipients.FileName)
		if _, err := os.Stat(p); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no %s found", recipients.FileName)
		}
		dir = parent
	}
}
