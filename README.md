# cryptree

Age-encrypted secret store organized as a file tree. Secrets are encrypted to a set of recipients defined per directory, making it safe to sync the tree via Nextcloud, Google Drive, or any file sync service.

Each machine holds its own private key. Secrets are encrypted with [age](https://age-encryption.org/) to all recipients listed in `.cryptree_recipients` files. No config file needed — the tool is fully convention-driven.

## Quick start

```bash
# Generate a keypair for this machine
cryptree keygen --name laptop
# prints: age1abc...

# Set up a secret tree
mkdir -p ~/secrets
echo "age1abc..." > ~/secrets/.cryptree_recipients

# Encrypt a secret
echo -n "hunter2" | cryptree encrypt ~/secrets/db-password.yaml

# Decrypt it
cryptree decrypt ~/secrets/db-password.yaml

# Add a second machine's key and re-encrypt
echo "age1def..." >> ~/secrets/.cryptree_recipients
cryptree re-encrypt ~/secrets
```

## CLI

```
cryptree keygen [--name <label>] [--add-recipient] [--re-encrypt]
cryptree encrypt <path> [--attr key=value ...] [--replace | --update]
cryptree decrypt <path>
cryptree re-encrypt [--dry-run] [--force] <path>...
```

## Tree structure

```
secrets/
├── .cryptree_recipients    # age public keys, one per line
├── db-password.yaml
├── api-token.yaml
└── work/
    ├── .cryptree_recipients  # overrides parent (replace semantics)
    └── deploy-key.yaml
```

`.cryptree_recipients` files are inherited recursively. A file in a subdirectory completely replaces the parent's recipient list for that subtree.

## File format

Secret files use YAML with an enforced `.yaml` extension:

```yaml
version: 1
recipients:
    - age1abc...
    - age1def...
attributes:
    env: production
    service: api
created: 2026-05-20T12:00:00Z
modified: 2026-05-20T12:00:00Z
payload: |
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBh...
```

## Keyring

Private keys are stored as standard age identity files in the platform data directory:

| Platform | Path |
|----------|------|
| Linux | `~/.local/share/cryptree/keys/` |
| macOS | `~/Library/Application Support/cryptree/keys/` |
| Windows | `%LOCALAPPDATA%\cryptree\keys\` |

Key files use `0600` permissions, the directory uses `0700`.

## Commands in detail

### keygen

Generates an age X25519 keypair and stores it in the keyring. Prints the public key to stdout.

- `--name <label>` — custom filename for the key (default: derived from public key)
- `--add-recipient` — append the public key to the nearest `.cryptree_recipients`
- `--re-encrypt` — re-encrypt all secrets in the tree with the updated recipient list

### encrypt

Reads raw bytes from stdin and writes an encrypted `.yaml` file. Resolves recipients by walking up to find the nearest `.cryptree_recipients`.

- Fails if the file already exists unless `--replace` or `--update` is given
- `--replace` — overwrites completely (fresh timestamps)
- `--update` — preserves `created` timestamp and merges attributes
- `--attr key=value` — set an attribute; `--attr key=` removes it

### decrypt

Decrypts a secret file and writes raw bytes to stdout. Loads all keys from the keyring and tries each one. Exit code 2 if no key matches.

### re-encrypt

Re-encrypts secrets whose stored recipients differ from the current `.cryptree_recipients`. Accepts any number of file or directory paths.

- `--dry-run` — list files that would change without modifying anything
- `--force` — re-encrypt unconditionally (useful for symmetric key rotation)

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Decryption failure (no matching private key) |

## Building

```bash
# With Nix
nix build

# With Go
go build ./cmd/cryptree
```
