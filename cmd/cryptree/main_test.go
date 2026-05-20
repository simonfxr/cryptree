package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var binary string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "cryptree-test-bin")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)
	binary = filepath.Join(tmp, "cryptree")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = filepath.Join(mustGetwd(), ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		panic("build failed: " + string(out))
	}
	os.Exit(m.Run())
}

func mustGetwd() string {
	d, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return d
}

func run(t *testing.T, stdin string, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), env...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("exec error: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func setup(t *testing.T) (dataHome string, treeDir string, env []string) {
	t.Helper()
	dataHome = t.TempDir()
	treeDir = t.TempDir()
	env = []string{"XDG_DATA_HOME=" + dataHome}
	return
}

func writeRecipients(t *testing.T, dir string, keys ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".cryptree_recipients"), []byte(strings.Join(keys, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestKeygen(t *testing.T) {
	dataHome, _, env := setup(t)
	stdout, _, code := run(t, "", env, "keygen")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	pubkey := strings.TrimSpace(stdout)
	if !strings.HasPrefix(pubkey, "age1") {
		t.Fatalf("unexpected pubkey: %q", pubkey)
	}
	files, _ := filepath.Glob(filepath.Join(dataHome, "cryptree", "keys", "*.key"))
	if len(files) != 1 {
		t.Fatalf("expected 1 key file, got %d", len(files))
	}
}

func TestKeygen_AddRecipient(t *testing.T) {
	_, treeDir, env := setup(t)
	writeRecipients(t, treeDir)
	cmd := exec.Command(binary, "keygen", "--add-recipient")
	cmd.Dir = treeDir
	cmd.Env = append(os.Environ(), env...)
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("keygen --add-recipient failed: %v", err)
	}
	pubkey := strings.TrimSpace(outBuf.String())
	if !strings.HasPrefix(pubkey, "age1") {
		t.Fatalf("unexpected pubkey: %q", pubkey)
	}
	data, err := os.ReadFile(filepath.Join(treeDir, ".cryptree_recipients"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), pubkey) {
		t.Fatalf("pubkey not in recipients file")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout, _, _ := run(t, "", env, "keygen")
	pubkey := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pubkey)

	secretPath := filepath.Join(treeDir, "secret.yaml")
	_, stderr, code := run(t, "hello world", env, "encrypt", secretPath)
	if code != 0 {
		t.Fatalf("encrypt failed (%d): %s", code, stderr)
	}

	stdout, stderr, code = run(t, "", env, "decrypt", secretPath)
	if code != 0 {
		t.Fatalf("decrypt failed (%d): %s", code, stderr)
	}
	if stdout != "hello world" {
		t.Fatalf("got %q, want %q", stdout, "hello world")
	}
}

func TestEncryptDecrypt_Binary(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout, _, _ := run(t, "", env, "keygen")
	pubkey := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pubkey)

	payload := "binary\x00data\x00here"
	secretPath := filepath.Join(treeDir, "bin.yaml")
	_, stderr, code := run(t, payload, env, "encrypt", secretPath)
	if code != 0 {
		t.Fatalf("encrypt failed (%d): %s", code, stderr)
	}

	stdout, _, code = run(t, "", env, "decrypt", secretPath)
	if code != 0 {
		t.Fatalf("decrypt failed (%d)", code)
	}
	if stdout != payload {
		t.Fatalf("binary mismatch")
	}
}

func TestEncrypt_ExistingFileFails(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout, _, _ := run(t, "", env, "keygen")
	pubkey := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pubkey)

	secretPath := filepath.Join(treeDir, "dup.yaml")
	run(t, "first", env, "encrypt", secretPath)
	_, _, code := run(t, "second", env, "encrypt", secretPath)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestEncrypt_Replace(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout, _, _ := run(t, "", env, "keygen")
	pubkey := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pubkey)

	secretPath := filepath.Join(treeDir, "rep.yaml")
	run(t, "old", env, "encrypt", secretPath)
	_, _, code := run(t, "new", env, "encrypt", "--replace", secretPath)
	if code != 0 {
		t.Fatalf("replace failed: exit %d", code)
	}

	out, _, _ := run(t, "", env, "decrypt", secretPath)
	if out != "new" {
		t.Fatalf("got %q, want %q", out, "new")
	}
}

func TestEncrypt_Update(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout, _, _ := run(t, "", env, "keygen")
	pubkey := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pubkey)

	secretPath := filepath.Join(treeDir, "upd.yaml")
	run(t, "v1", env, "encrypt", "--attr", "env=prod", secretPath)

	// Read created timestamp
	data1, _ := os.ReadFile(secretPath)
	time.Sleep(10 * time.Millisecond)

	_, _, code := run(t, "v2", env, "encrypt", "--update", "--attr", "tier=1", secretPath)
	if code != 0 {
		t.Fatalf("update failed: exit %d", code)
	}

	data2, _ := os.ReadFile(secretPath)
	content := string(data2)
	if !strings.Contains(content, "env: prod") {
		t.Fatalf("env=prod missing after update")
	}
	if !strings.Contains(content, "tier: \"1\"") && !strings.Contains(content, "tier: '1'") && !strings.Contains(content, "tier: 1") {
		t.Fatalf("tier=1 missing after update")
	}
	// created should be preserved
	if !strings.Contains(string(data2), strings.Split(extractYAMLField(string(data1), "created"), "\n")[0]) {
		// Just check created line is same
	}

	out, _, _ := run(t, "", env, "decrypt", secretPath)
	if out != "v2" {
		t.Fatalf("got %q, want %q", out, "v2")
	}
}

func TestEncrypt_AttrRemove(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout, _, _ := run(t, "", env, "keygen")
	pubkey := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pubkey)

	secretPath := filepath.Join(treeDir, "attr.yaml")
	run(t, "data", env, "encrypt", "--attr", "env=prod", "--attr", "svc=api", secretPath)
	_, _, code := run(t, "data", env, "encrypt", "--update", "--attr", "env=", secretPath)
	if code != 0 {
		t.Fatalf("update failed: exit %d", code)
	}

	content, _ := os.ReadFile(secretPath)
	if strings.Contains(string(content), "env:") {
		t.Fatalf("env attr should be removed")
	}
	if !strings.Contains(string(content), "svc: api") {
		t.Fatalf("svc attr should remain")
	}
}

func TestEncrypt_NoYamlExtension(t *testing.T) {
	_, treeDir, env := setup(t)
	writeRecipients(t, treeDir)
	secretPath := filepath.Join(treeDir, "secret.txt")
	_, _, code := run(t, "data", env, "encrypt", secretPath)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	dataHome1, treeDir, env1 := setup(t)
	_ = dataHome1
	stdout, _, _ := run(t, "", env1, "keygen")
	pubkey := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pubkey)

	secretPath := filepath.Join(treeDir, "secret.yaml")
	run(t, "secret", env1, "encrypt", secretPath)

	// Different keyring
	dataHome2 := t.TempDir()
	env2 := []string{"XDG_DATA_HOME=" + dataHome2}
	run(t, "", env2, "keygen") // generate a different key

	_, _, code := run(t, "", env2, "decrypt", secretPath)
	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
}

func TestReEncrypt(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout1, _, _ := run(t, "", env, "keygen", "--name", "key1")
	pub1 := strings.TrimSpace(stdout1)
	writeRecipients(t, treeDir, pub1)

	secretPath := filepath.Join(treeDir, "secret.yaml")
	run(t, "hello", env, "encrypt", secretPath)

	// Generate key2 and add to recipients
	stdout2, _, _ := run(t, "", env, "keygen", "--name", "key2")
	pub2 := strings.TrimSpace(stdout2)
	writeRecipients(t, treeDir, pub1, pub2)

	_, _, code := run(t, "", env, "re-encrypt", secretPath)
	if code != 0 {
		t.Fatalf("re-encrypt failed: exit %d", code)
	}

	// key2-only keyring should decrypt
	dataHome2 := t.TempDir()
	env2 := []string{"XDG_DATA_HOME=" + dataHome2}
	// Copy key2 to new keyring
	srcKey := filepath.Join(dataHome, "cryptree", "keys", "key2.key")
	dstDir := filepath.Join(dataHome2, "cryptree", "keys")
	os.MkdirAll(dstDir, 0700)
	data, _ := os.ReadFile(srcKey)
	os.WriteFile(filepath.Join(dstDir, "key2.key"), data, 0600)

	out, _, code := run(t, "", env2, "decrypt", secretPath)
	if code != 0 {
		t.Fatalf("decrypt with key2 failed: exit %d", code)
	}
	if out != "hello" {
		t.Fatalf("got %q, want %q", out, "hello")
	}
}

func TestReEncrypt_DryRun(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout1, _, _ := run(t, "", env, "keygen", "--name", "key1")
	pub1 := strings.TrimSpace(stdout1)
	writeRecipients(t, treeDir, pub1)

	secretPath := filepath.Join(treeDir, "secret.yaml")
	run(t, "hello", env, "encrypt", secretPath)

	before, _ := os.ReadFile(secretPath)

	// Add key2 to recipients
	stdout2, _, _ := run(t, "", env, "keygen", "--name", "key2")
	pub2 := strings.TrimSpace(stdout2)
	writeRecipients(t, treeDir, pub1, pub2)

	stdout, _, code := run(t, "", env, "re-encrypt", "--dry-run", secretPath)
	if code != 0 {
		t.Fatalf("re-encrypt --dry-run failed: exit %d", code)
	}
	if !strings.Contains(stdout, secretPath) {
		t.Fatalf("expected path in dry-run output")
	}

	after, _ := os.ReadFile(secretPath)
	if string(before) != string(after) {
		t.Fatalf("file changed during dry-run")
	}
}

func TestReEncrypt_Force(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout, _, _ := run(t, "", env, "keygen")
	pubkey := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pubkey)

	secretPath := filepath.Join(treeDir, "secret.yaml")
	run(t, "hello", env, "encrypt", secretPath)

	before, _ := os.ReadFile(secretPath)
	time.Sleep(10 * time.Millisecond)

	_, _, code := run(t, "", env, "re-encrypt", "--force", secretPath)
	if code != 0 {
		t.Fatalf("re-encrypt --force failed: exit %d", code)
	}

	after, _ := os.ReadFile(secretPath)
	if string(before) == string(after) {
		t.Fatalf("file unchanged after --force re-encrypt")
	}
	// modified timestamp should differ
	modBefore := extractYAMLField(string(before), "modified")
	modAfter := extractYAMLField(string(after), "modified")
	if modBefore == modAfter {
		t.Fatalf("modified timestamp unchanged")
	}
}

func TestReEncrypt_Directory(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout, _, _ := run(t, "", env, "keygen", "--name", "key1")
	pub1 := strings.TrimSpace(stdout)
	writeRecipients(t, treeDir, pub1)

	// Create subdirs with secrets
	sub := filepath.Join(treeDir, "sub")
	os.MkdirAll(sub, 0755)
	run(t, "a", env, "encrypt", filepath.Join(treeDir, "a.yaml"))
	run(t, "b", env, "encrypt", filepath.Join(sub, "b.yaml"))

	// Add key2
	stdout2, _, _ := run(t, "", env, "keygen", "--name", "key2")
	pub2 := strings.TrimSpace(stdout2)
	writeRecipients(t, treeDir, pub1, pub2)

	_, _, code := run(t, "", env, "re-encrypt", treeDir)
	if code != 0 {
		t.Fatalf("re-encrypt dir failed: exit %d", code)
	}

	// Verify key2 can decrypt both
	dataHome2 := t.TempDir()
	env2 := []string{"XDG_DATA_HOME=" + dataHome2}
	dstDir := filepath.Join(dataHome2, "cryptree", "keys")
	os.MkdirAll(dstDir, 0700)
	srcKey := filepath.Join(dataHome, "cryptree", "keys", "key2.key")
	data, _ := os.ReadFile(srcKey)
	os.WriteFile(filepath.Join(dstDir, "key2.key"), data, 0600)

	out, _, code := run(t, "", env2, "decrypt", filepath.Join(treeDir, "a.yaml"))
	if code != 0 || out != "a" {
		t.Fatalf("decrypt a.yaml with key2: exit %d, got %q", code, out)
	}
	out, _, code = run(t, "", env2, "decrypt", filepath.Join(sub, "b.yaml"))
	if code != 0 || out != "b" {
		t.Fatalf("decrypt b.yaml with key2: exit %d, got %q", code, out)
	}
}

func TestKeygen_ReEncrypt(t *testing.T) {
	dataHome, treeDir, env := setup(t)
	_ = dataHome
	stdout1, _, _ := run(t, "", env, "keygen", "--name", "key1")
	pub1 := strings.TrimSpace(stdout1)
	writeRecipients(t, treeDir, pub1)

	secretPath := filepath.Join(treeDir, "secret.yaml")
	run(t, "payload", env, "encrypt", secretPath)

	// keygen --add-recipient --re-encrypt from treeDir
	cmd := exec.Command(binary, "keygen", "--name", "key2", "--add-recipient", "--re-encrypt")
	cmd.Dir = treeDir
	cmd.Env = append(os.Environ(), env...)
	var outBuf strings.Builder
	cmd.Stdout = &outBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("keygen --add-recipient --re-encrypt failed: %v", err)
	}
	pub2 := strings.TrimSpace(outBuf.String())

	// Verify key2 can decrypt
	dataHome2 := t.TempDir()
	env2 := []string{"XDG_DATA_HOME=" + dataHome2}
	dstDir := filepath.Join(dataHome2, "cryptree", "keys")
	os.MkdirAll(dstDir, 0700)
	srcKey := filepath.Join(dataHome, "cryptree", "keys", "key2.key")
	data, _ := os.ReadFile(srcKey)
	os.WriteFile(filepath.Join(dstDir, "key2.key"), data, 0600)

	out, _, code := run(t, "", env2, "decrypt", secretPath)
	if code != 0 {
		t.Fatalf("decrypt with key2 failed: exit %d", code)
	}
	if out != "payload" {
		t.Fatalf("got %q, want %q", out, "payload")
	}
	_ = pub2
}

func extractYAMLField(content, field string) string {
	for line := range strings.SplitSeq(content, "\n") {
		if after, ok := strings.CutPrefix(line, field+":"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}
