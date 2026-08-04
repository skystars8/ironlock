# Ironlock 🔐

[![Crates.io](https://img.shields.io/crates/v/ironlock.svg)](https://crates.io/crates/ironlock)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/christurgeon/ironlock/actions/workflows/ci.yaml/badge.svg)](https://github.com/christurgeon/ironlock/actions/workflows/ci.yaml)

A secure file encryption CLI tool built in Rust. Ironlock uses industry-standard cryptographic primitives to protect your files with a password.

## Installation

### From crates.io (recommended)

```bash
cargo install ironlock
```

### From Source

```bash
git clone https://github.com/christurgeon/ironlock.git
cd ironlock
cargo build --release
cp ./target/release/ironlock ~/.local/bin/
```

## Quick Start

```bash
# Encrypt a file (password prompt will appear)
ironlock encrypt secret.txt
# Creates: secret.il

# Decrypt a file
ironlock decrypt secret.il
# Restores: secret.txt
```

## Usage

### Encrypt Files

```bash
# Encrypt a single file
ironlock encrypt secret.txt

# Encrypt multiple files
ironlock encrypt document.pdf image.png notes.md

# Force overwrite of existing .il files
ironlock encrypt secret.txt --force

# Best-effort overwrite/delete originals after encryption (see limitations below)
ironlock encrypt secret.txt --shred

# Combine flags
ironlock encrypt secret.txt -f -s
```

You'll be prompted to enter and confirm your password (hidden input):

```
🔐 Ironlock Encryption

Enter password:
Confirm password:

Encrypting secret.txt ... ✓ → secret.il
```

> **Format note:** New v2 files encrypt the original filename and extension as authenticated metadata. Legacy v1 files still decrypt, but v1 stored the filename in its public header; re-encrypt sensitive v1 files to migrate them.
> If same-stem inputs would collide (for example `report.txt` and `report.pdf`), Ironlock assigns distinct randomized `.il` names during batch preflight.

### Decrypt Files

```bash
# Decrypt a single file
ironlock decrypt secret.il

# Decrypt to a specific directory
ironlock decrypt secret.il --output ./decrypted/

# Decrypt multiple files
ironlock decrypt file1.il file2.il file3.il -o ./output/

# Force overwrite of existing files
ironlock decrypt secret.il --force
```

### Directory Encryption

Ironlock can recursively encrypt or decrypt entire directories, preserving the directory structure:

```bash
# Encrypt all files in a directory
ironlock encrypt ./my-folder/

# Decrypt all .il files in a directory to an output location
ironlock decrypt ./my-folder/ -o ./decrypted/

# Encrypt a directory and best-effort overwrite/delete the originals
ironlock encrypt ./sensitive-docs/ --shred
```

Directory encryption rejects links/reparse points and skips existing `.il` files. All input/output paths are planned before the first file is changed.

### Piping (Stdin/Stdout)

Ironlock supports reading from stdin and writing to stdout for composability with other tools. When no files are provided and stdin is piped, Ironlock operates in streaming mode:

```bash
# Encrypt from stdin to a file
cat secret.txt | ironlock encrypt > secret.il

# Decrypt from stdin to a file
cat secret.il | ironlock decrypt > secret.txt

# Chain with other tools
tar cf - ./docs/ | ironlock encrypt > docs.tar.il
cat docs.tar.il | ironlock decrypt | tar xf -
```

Password prompts are written to stderr, so they won't interfere with piped data.

### Command Aliases

For convenience, shorthand aliases are available:

| Command | Aliases |
|---------|---------|
| `encrypt` | `enc`, `e` |
| `decrypt` | `dec`, `d` |

```bash
ironlock e secret.txt        # same as: ironlock encrypt secret.txt
ironlock d secret.il -o out/ # same as: ironlock decrypt secret.il -o out/
```

### Flags Reference

#### Encrypt

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Overwrite existing `.il` files without prompting |
| `--shred` | `-s` | Best-effort 3-pass overwrite and delete (also `--delete`; media-dependent) |
| `--progress` | `-p` | Show a progress bar when processing multiple files |

#### Decrypt

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Overwrite existing output files without prompting |
| `--output <DIR>` | `-o` | Output directory for decrypted files |
| `--progress` | `-p` | Show a progress bar when processing multiple files |

## Security

Ironlock uses the following cryptographic primitives:

- **Argon2id** for password-based key derivation (64 MiB memory, 3 iterations, 4 parallelism)
- **ChaCha20-Poly1305** for authenticated encryption (256-bit keys, 96-bit nonces)
- **Authenticated streaming** — v2 encrypts independent 64 KiB records with authenticated sequence numbers plus a final authenticated byte/chunk count, detecting tampering, reordering, and truncation
- **Encrypted metadata** — original filenames/extensions are inside the encrypted metadata record, not the public v2 header
- **Bounded parsing** — KDF costs, chunk sizes, record lengths, counters, and legacy-file size are checked before allocation/work
- **Atomic private outputs** — data is written to an owner-only temporary file, synced, and atomically installed; links/reparse points are rejected
- **Secure memory handling** via `zeroize` for passwords, keys, plaintext chunks, metadata, and legacy plaintext, plus best-effort `mlock` on Unix
- **Best-effort deletion** — `--shred` overwrites in fixed-size chunks three times before unlinking

KDF parameters remain in the public authenticated header so the key can be derived, but readers enforce strict work-factor limits before running Argon2. v2 uses Argon2id with a fresh salt and derives unique per-record ChaCha20-Poly1305 nonces from a random base nonce and authenticated sequence number.

Version 2 streams file and stdin/stdout operations with bounded memory. Decryption of legacy v1 files remains one-shot and is capped at 256 MiB.

> **Deletion limitation:** `--shred` cannot guarantee media sanitization on SSDs, copy-on-write or journaled filesystems, snapshots, cloud storage, or backups. Prefer full-volume encryption and storage-native sanitize or cryptographic-erase procedures when recovery resistance matters.

## Development

```bash
# Run tests
cargo test

# Run lints
cargo clippy

# Format code
cargo fmt

# Build release
cargo build --release
```

## Uninstalling

```bash
cargo uninstall ironlock
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT License - see [LICENSE](LICENSE) for details.
