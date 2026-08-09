# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Expanded deterministic unit and executable-level CLI contract coverage across
  cryptography, hostile-format parsing, short/interrupted I/O, filesystem
  identity, atomic output, secure deletion, CLI validation, and typed errors
- Added a security reporting policy, Dependabot configuration, MSRV checks,
  release-package verification, and locked cross-platform CI

### Security

- Added encrypted-file format v2 with encrypted filename metadata and bounded, independently authenticated streaming records
- Added strict pre-allocation limits for KDF work factors, chunk sizes, record lengths, counters, and legacy files
- Added collision-safe batch preflight, hard-link identity deduplication,
  symlink/reparse-point rejection, private atomic output files, and file-identity
  revalidation
- Prevented authenticated decryption outputs from replacing pending batch
  ciphertexts or earlier outputs with the same recovered filename
- Bound destructive `--shred` and forced replacement to the exact file
  identities observed before processing; multi-linked files are refused
- Changed `--shred` to fixed-memory best-effort overwrite/delete behavior and documented storage-media limitations
- Preserved read compatibility with v1 encrypted files

### Changed

- Batch commands now return a non-zero exit status when any file fails or is skipped
- Directory encryption skips existing `.il` files and rejects links instead of following them
- stdin/stdout and regular v2 file operations now use bounded streaming
- File-only flags are rejected in stdin/stdout mode instead of being silently
  ignored, and empty/non-matching directory batches fail before password entry
- CLI status output now uses portable text labels and precise security wording
- Release builds enable integer overflow checks

### Fixed

- Rejected empty v2 filenames at encryption time to match decryption invariants
- Removed duplicate CI workflows, unpinned audit installation, unlocked checks,
  and development-only files from the release package

## [0.1.0] - 2026-03-20

### Added

- File encryption and decryption using Argon2id + ChaCha20-Poly1305
- Authenticated header via AEAD associated data
- Multi-file and directory support with recursive traversal
- Stdin/stdout piping for composability with other tools
- `--shred` flag for secure deletion (3-pass random overwrite)
- `--force` flag to overwrite existing files
- `--output` flag for custom decryption output directory
- `--progress` / `-p` flag to show a progress bar
- Large file warning for files over 1 GiB
- Command aliases (`e`/`enc` for encrypt, `d`/`dec` for decrypt)
- Secure memory handling with `zeroize` and `mlock`
- KDF parameters stored in file header for forward compatibility
- Colored terminal output with progress indicators
- GitHub Actions CI (test, clippy, fmt)

[0.1.0]: https://github.com/christurgeon/ironlock/releases/tag/v0.1.0
[Unreleased]: https://github.com/christurgeon/ironlock/compare/v0.1.0...HEAD
