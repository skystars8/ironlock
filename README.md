# Ironlock 🔐

[![Crates.io](https://img.shields.io/crates/v/ironlock.svg)](https://crates.io/crates/ironlock)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/christurgeon/ironlock/actions/workflows/ci.yaml/badge.svg)](https://github.com/christurgeon/ironlock/actions/workflows/ci.yaml)

A password-based authenticated file-encryption CLI built in Rust. Ironlock uses
Argon2id and ChaCha20-Poly1305, streams large files with bounded memory, and
commits private outputs atomically.

> **Important:** Encryption software cannot replace backups or recovery tests.
> Ironlock has extensive automated coverage, but it has not received a formal
> cryptographic proof or an independent security assessment. Keep a recoverable
> copy until you have verified decryption with the exact release you intend to
> deploy.

## Installation

### From crates.io (recommended)

```bash
cargo install ironlock --locked
```

### From Source

```bash
git clone https://github.com/christurgeon/ironlock.git
cd ironlock
cargo build --release --locked
cp ./target/release/ironlock ~/.local/bin/
```

## Quick Start

```bash
# Encrypt a file (password prompt will appear)
ironlock encrypt secret.txt
# Creates: secret.il

# Decrypt a file
ironlock decrypt secret.il --output ./restored/
# Restores: ./restored/secret.txt without replacing the original
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
Ironlock Encryption

Enter password:
Confirm password:

Encrypting secret.txt ... [OK] -> secret.il
```

> **Format note:** New v2 files encrypt the exact original filename and
> extension as authenticated metadata. The default output path still retains
> the source stem (`secret.txt` becomes `secret.il`), so rename the `.il`
> file to an opaque name if the stem itself is sensitive. Legacy v1 files still
> decrypt, but v1 stored the full filename in its public header; re-encrypt
> sensitive v1 files to migrate them.
>
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

Directory encryption rejects links/reparse points, rejects duplicate file
identities such as hard-link aliases, and skips existing `.il` files. A
directory with no eligible files fails before password entry. Encryption paths
are planned before the first file is changed; authenticated decryption output
names are reserved as each file is opened.

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
File-only options such as `--force`, `--shred`, `--progress`, and
`--output` are rejected in stdin/stdout mode.
The password is still read interactively from a terminal; piped mode is not an
unattended/headless secret-injection interface.

When decrypting to stdout, every data record is authenticated before it is
written, but the final length and truncation check occurs only at end of stream.
Downstream automation must discard or roll back output unless Ironlock exits
successfully.

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
| `--progress` | `-p` | Show a progress bar while processing files |

#### Decrypt

| Flag | Short | Description |
|------|-------|-------------|
| `--force` | `-f` | Overwrite existing output files without prompting |
| `--output <DIR>` | `-o` | Output directory for decrypted files |
| `--progress` | `-p` | Show a progress bar while processing files |

### Exit Status

| Code | Meaning |
|------|---------|
| `0` | Every requested operation completed successfully |
| `1` | An operational, authentication, safety, or incomplete-batch error occurred |
| `2` | Command-line usage was invalid |

Batch operations continue where safe so independent files can complete, then
return code `1` if any item failed or was skipped. A batch is not a
transaction: outputs committed before a later failure remain in place.

## Security Model

Ironlock uses the following cryptographic primitives:

- **Argon2id** for password-based key derivation (64 MiB memory, 3 iterations, 4 parallelism)
- **ChaCha20-Poly1305** for authenticated encryption (256-bit keys, 96-bit nonces)
- **Authenticated streaming** — v2 encrypts independent 64 KiB records with authenticated sequence numbers plus a final authenticated byte/chunk count, detecting tampering, reordering, and truncation
- **Encrypted metadata** — original filenames/extensions are inside the encrypted metadata record, not the public v2 header
- **Bounded parsing** — KDF costs, chunk sizes, record lengths, counters, and legacy-file size are checked before allocation/work
- **Atomic private outputs** — on Linux, macOS, and Windows, data is written to an owner-only temporary file, synced, and atomically installed; links/reparse points are rejected
- **Best-effort secure memory handling** — app-owned password, key, streaming-chunk, metadata, and legacy buffers use zeroization; stable password/key allocations also use best-effort OS memory locking
- **Best-effort deletion** — `--shred` overwrites in fixed-size chunks three times before unlinking

KDF parameters remain in the public authenticated header so the key can be derived, but readers enforce strict work-factor limits before running Argon2. v2 uses Argon2id with a fresh salt and derives unique per-record ChaCha20-Poly1305 nonces from a random base nonce and authenticated sequence number.

Version 2 streams file and stdin/stdout operations with bounded memory. Decryption of legacy v1 files remains one-shot and is capped at 256 MiB.

Linux, macOS, and Windows are the production-supported targets. Other targets
may compile, but do not provide the same private-file/atomic-rename guarantees;
`--shred` refuses to run where the required atomic no-replace primitive is not
available.

### Passwords and Recovery

- There is no password reset, escrow, or recovery key. A lost password means the
  encrypted data is unrecoverable.
- Use a long, unique passphrase from a password manager. Ironlock deliberately
  does not accept passwords in command-line arguments or environment variables,
  where they are easier to expose.
- Authentication failures intentionally do not distinguish a wrong password
  from corrupted ciphertext.

### Filesystem Guarantees

- Input batches are validated before password entry or file modification.
  Symbolic links, reparse points, duplicate paths, and duplicate file identities
  are rejected.
- Authenticated decryption output names are reserved within a batch so an output
  cannot replace a pending ciphertext or another output from the same command.
- Outputs are written to unpredictable owner-only temporary files, flushed,
  synchronized, and atomically installed. An unexpected destination that appears
  during processing is not silently clobbered.
- These guarantees are per file. They do not make a multi-file batch
  transactional across crashes, power loss, or later-item failures.

### Known Limitations

- **Best-effort deletion:** `--shred` cannot guarantee media sanitization on
  SSDs, flash translation layers, copy-on-write or journaled filesystems,
  snapshots, swap, cloud storage, backups, or prior copies. Prefer full-volume
  encryption and storage-native sanitize or cryptographic-erase procedures.
  On Unix and Windows, Ironlock refuses to shred a file whose observed hard-link
  count is not exactly one.
- **Legacy metadata:** v1 ciphertext exposes its original filename. Decrypt and
  re-encrypt it to create v2 data. Legacy decryption buffers the complete
  ciphertext and plaintext and accepts at most a 256 MiB encrypted input, so
  allow additional memory headroom during migration. Ironlock releases that
  only understand v1 cannot decrypt newly created v2 files.
- **Visible metadata:** the default `.il` path retains the source stem, public
  KDF parameters are visible, and ciphertext length approximates plaintext
  length. Rename ciphertext when the stem is sensitive.
- **Streaming consumers:** stdout may contain an authenticated plaintext prefix
  before a missing or invalid final record is detected. Trust the stream only
  after exit code `0`.
- **Host compromise:** Ironlock cannot protect a password or plaintext from a
  compromised process, operating system, terminal, keylogger, or malicious
  hardware.
- **Hostile shared directories:** Ironlock validates path components and pins
  file identities where practical, but it does not hold handles to every
  ancestor directory for an entire operation. Do not process sensitive files
  in directories that an untrusted user can rename or replace concurrently.
- **Memory copies:** zeroization and memory locking cover buffers directly owned
  by Ironlock where practical. They cannot guarantee removal of copies made by
  allocators, standard-library buffering, dependencies, the OS, terminal,
  caches, swap, crash dumps, or hardware.
- **Filename portability:** file encryption currently requires the final source
  filename to be valid UTF-8. This can reject otherwise valid non-Unicode names
  on Unix.
- **Assurance:** this implementation has not undergone an independent
  penetration test, formal verification, or a dedicated fuzzing campaign.
- **Interrupted writes:** normal errors clean up temporary outputs, but a process
  abort, power loss, or machine crash can leave an owner-only
  `.ironlock-*.tmp` file in the destination directory. Treat a leftover file
  as sensitive and inspect/remove it deliberately.

## Production Checklist

1. Keep an independent backup and perform a real restore test before deleting
   plaintext.
2. Use a unique high-entropy passphrase and store it separately from the
   ciphertext.
3. Install/build with `--locked`; do not ignore a non-zero exit status.
4. Verify a representative encrypted file after upgrades and before relying on
   `--shred`.
5. Prefer full-volume encryption for temporary files, swap, filesystem metadata,
   and deletion-at-rest guarantees that a file-level tool cannot provide.
6. Preserve the Ironlock version and platform details needed for incident or
   recovery work.

Encryption commits and syncs the ciphertext before attempting `--shred`. If
shredding fails, Ironlock returns code `1`; a valid ciphertext may coexist
with a restored, partially overwritten, or otherwise undeleted source. Inspect
both paths before retrying.

## Development

```bash
# Core local gates (CI additionally sets RUSTDOCFLAGS=-D warnings)
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo doc --no-deps --locked
cargo +1.92.0 check --all-targets --locked
cargo install cargo-audit --version 0.22.2 --locked
cargo audit
cargo package --locked
cargo build --release --locked
```

CI runs locked tests on Linux, macOS, and Windows, checks the declared Rust 1.92
minimum, treats Clippy and documentation warnings as failures, verifies the
release package and optimized build, and scans `Cargo.lock` with a pinned
`cargo-audit`. Dependabot monitors both Cargo and GitHub Actions dependencies.

## Uninstalling

```bash
cargo uninstall ironlock
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Security vulnerabilities should be reported privately as described in
[SECURITY.md](SECURITY.md), not opened as public issues.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT License - see [LICENSE](LICENSE) for details.
