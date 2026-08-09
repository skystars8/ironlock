use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::{IronlockError, Result};
use crate::memlock::LockedBytes;

/// Ironlock file format magic bytes - identifies our encrypted files
pub const MAGIC_BYTES: &[u8; 8] = b"IRONLOCK";

/// Version of the file format (for future compatibility)
pub const FORMAT_VERSION: u8 = 1;

/// Salt length for Argon2id (16 bytes = 128 bits, recommended minimum)
pub const SALT_LENGTH: usize = 16;

/// Nonce length for ChaCha20-Poly1305 (12 bytes = 96 bits, standard)
pub const NONCE_LENGTH: usize = 12;

/// Key length for ChaCha20-Poly1305 (32 bytes = 256 bits)
pub const KEY_LENGTH: usize = 32;

/// Stable-address, zeroizing key storage with best-effort memory locking.
pub type LockedKey = LockedBytes<KEY_LENGTH>;

/// Argon2id parameters - tuned for security
/// These parameters provide strong resistance against GPU/ASIC attacks
/// - Memory: 64 MiB
/// - Iterations: 3
/// - Parallelism: 4
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Hard limits applied before allocating Argon2 work memory. File headers are
/// attacker-controlled until AEAD authentication succeeds, so accepting the
/// crate's u32::MAX limits would permit enormous allocations or CPU work.
pub const MAX_ARGON2_MEMORY_KIB: u32 = 128 * 1024;
pub const MAX_ARGON2_ITERATIONS: u32 = 6;
pub const MAX_ARGON2_PARALLELISM: u32 = 8;

pub const MIN_ARGON2_MEMORY_KIB: u32 = 8;
pub const MIN_ARGON2_ITERATIONS: u32 = 1;
pub const MIN_ARGON2_PARALLELISM: u32 = 1;

/// Argon2id key derivation parameters stored in the file header
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// Returns the current default (strongest) parameters for new encryptions
    pub fn current() -> Self {
        Self {
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        }
    }
}

/// Rejects unreasonable KDF work factors before the Argon2 crate can allocate.
pub fn validate_kdf_params(kdf_params: &KdfParams) -> Result<()> {
    if !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&kdf_params.memory_kib) {
        return Err(IronlockError::ResourceLimit(format!(
            "Argon2 memory cost must be between {} and {} KiB",
            MIN_ARGON2_MEMORY_KIB, MAX_ARGON2_MEMORY_KIB
        )));
    }
    if !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&kdf_params.iterations) {
        return Err(IronlockError::ResourceLimit(format!(
            "Argon2 iterations must be between {} and {}",
            MIN_ARGON2_ITERATIONS, MAX_ARGON2_ITERATIONS
        )));
    }
    if !(MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&kdf_params.parallelism) {
        return Err(IronlockError::ResourceLimit(format!(
            "Argon2 parallelism must be between {} and {}",
            MIN_ARGON2_PARALLELISM, MAX_ARGON2_PARALLELISM
        )));
    }
    if kdf_params.memory_kib < kdf_params.parallelism * 8 {
        return Err(IronlockError::InvalidFileFormat);
    }
    Ok(())
}

/// Derives a 256-bit encryption key from a password using Argon2id
///
/// Argon2id is the recommended password hashing algorithm, combining:
/// - Argon2i: resistance against side-channel attacks
/// - Argon2d: resistance against GPU cracking attacks
///
/// The salt ensures that the same password produces different keys for different files.
///
/// The derived key is written directly into stable heap storage that is
/// memory-locked on a best-effort basis. It is zeroized before being unlocked
/// and deallocated when the returned guard is dropped.
pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8],
    kdf_params: &KdfParams,
) -> Result<LockedKey> {
    validate_kdf_params(kdf_params)?;

    let params = Params::new(
        kdf_params.memory_kib,
        kdf_params.iterations,
        kdf_params.parallelism,
        Some(KEY_LENGTH),
    )
    .map_err(|e| IronlockError::EncryptionFailed(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Allocate and attempt to lock the final storage before Argon2 writes the
    // derived key. Moving LockedKey never moves this boxed allocation.
    let mut key = LockedKey::zeroed();
    argon2
        .hash_password_into(password, salt, key.as_mut_bytes())
        .map_err(|e| IronlockError::EncryptionFailed(format!("Key derivation failed: {}", e)))?;

    Ok(key)
}

/// Generates a cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generates a cryptographically secure random nonce
pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext data using ChaCha20-Poly1305
///
/// ChaCha20-Poly1305 is an authenticated encryption algorithm that provides:
/// - Confidentiality: data is encrypted with ChaCha20 stream cipher
/// - Integrity: Poly1305 MAC ensures that data hasn't been tampered with
/// - Authentication: verifies the cipher text was created with the correct key
///
/// The `aad` (associated data) is authenticated but not encrypted. Pass the file
/// header as AAD to bind it to the ciphertext. Pass `&[]` for no associated data.
///
/// Returns the ciphertext with the 16-byte authentication tag appended.
pub fn encrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| IronlockError::EncryptionFailed(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| IronlockError::EncryptionFailed(format!("Encryption failed: {}", e)))
}

/// Decrypts ciphertext using ChaCha20-Poly1305
///
/// This function also verifies the authentication tag, ensuring:
/// - The data hasn't been modified
/// - The correct password was used
/// - The associated data (`aad`) matches what was provided during encryption
///
/// Returns an error if authentication fails (wrong password, corrupted data,
/// or mismatched AAD).
pub fn decrypt(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| IronlockError::DecryptionFailed)?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| IronlockError::DecryptionFailed)
}

// Encrypted file structure (v1):
//
// | Offset | Size | Description                          |
// |--------|------|--------------------------------------|
// | 0      | 8    | Magic bytes "IRONLOCK"               |
// | 8      | 1    | Format version (1)                   |
// | 9      | 4    | Argon2 memory cost (u32 BE, in KiB)  |
// | 13     | 4    | Argon2 iterations (u32 BE)           |
// | 17     | 4    | Argon2 parallelism (u32 BE)          |
// | 21     | 2    | Original filename length (u16 BE)    |
// | 23     | N    | Original filename (UTF-8)            |
// | 23+N   | 16   | Argon2id salt                        |
// | 39+N   | 12   | ChaCha20 nonce                       |
// | 51+N   | ...  | Encrypted data + auth tag (16 bytes) |
//
// The entire header (bytes 0..51+N) is passed as associated data (AAD) to
// ChaCha20-Poly1305. This authenticates the header so that tampering with
// magic bytes, version, KDF params, filename, salt, or nonce is detected
// during decryption.

/// Creates the encrypted file format with all metadata using default KDF params
#[cfg(test)]
pub fn create_encrypted_file(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    create_encrypted_file_with_params(
        password,
        original_filename,
        plaintext,
        &KdfParams::current(),
    )
}

/// Creates the encrypted file format with all metadata using the specified KDF params
#[cfg(test)]
pub fn create_encrypted_file_with_params(
    password: &[u8],
    original_filename: &str,
    plaintext: &[u8],
    kdf_params: &KdfParams,
) -> Result<Vec<u8>> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let key = derive_key_from_password(password, &salt, kdf_params)?;

    let filename_bytes = original_filename.as_bytes();
    if filename_bytes.len() > u16::MAX as usize {
        return Err(IronlockError::EncryptionFailed(
            "Filename too long (exceeds 65535 bytes)".to_string(),
        ));
    }
    let filename_len = filename_bytes.len() as u16;

    // Build header (everything before ciphertext) — used as AAD
    let header_size = MAGIC_BYTES.len()
        + 1 // version
        + 4 // memory cost
        + 4 // iterations
        + 4 // parallelism
        + 2 // filename length
        + filename_bytes.len()
        + SALT_LENGTH
        + NONCE_LENGTH;

    let mut header = Vec::with_capacity(header_size);
    header.extend_from_slice(MAGIC_BYTES);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&kdf_params.memory_kib.to_be_bytes());
    header.extend_from_slice(&kdf_params.iterations.to_be_bytes());
    header.extend_from_slice(&kdf_params.parallelism.to_be_bytes());
    header.extend_from_slice(&filename_len.to_be_bytes());
    header.extend_from_slice(filename_bytes);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    // Encrypt with header as associated data (authenticated but not encrypted)
    let ciphertext = encrypt(&key, &nonce, plaintext, &header)?;

    // Reuse header allocation as output buffer
    header.reserve_exact(ciphertext.len());
    header.extend_from_slice(&ciphertext);

    Ok(header)
}

/// Parses an encrypted file and decrypts its contents
///
/// Returns: (original_filename, decrypted_data)
pub fn decrypt_file(password: &[u8], encrypted_data: &[u8]) -> Result<(String, Vec<u8>)> {
    // Minimum size: magic(8) + version(1) + kdf(12) + filename_len(2) + salt(16) + nonce(12) + tag(16) = 67
    const MINIMUM_SIZE: usize = 8 + 1 + 12 + 2 + 16 + 12 + 16;

    if encrypted_data.len() < MINIMUM_SIZE {
        return Err(IronlockError::InvalidFileFormat);
    }

    // Verify magic bytes
    if &encrypted_data[0..8] != MAGIC_BYTES {
        return Err(IronlockError::InvalidFileFormat);
    }

    // Check version
    if encrypted_data[8] != FORMAT_VERSION {
        return Err(IronlockError::InvalidFileFormat);
    }

    // Read KDF params from header
    let memory_kib = u32::from_be_bytes(
        encrypted_data[9..13]
            .try_into()
            .map_err(|_| IronlockError::InvalidFileFormat)?,
    );
    let iterations = u32::from_be_bytes(
        encrypted_data[13..17]
            .try_into()
            .map_err(|_| IronlockError::InvalidFileFormat)?,
    );
    let parallelism = u32::from_be_bytes(
        encrypted_data[17..21]
            .try_into()
            .map_err(|_| IronlockError::InvalidFileFormat)?,
    );
    let kdf_params = KdfParams {
        memory_kib,
        iterations,
        parallelism,
    };

    // Read filename length
    let filename_len = u16::from_be_bytes([encrypted_data[21], encrypted_data[22]]) as usize;

    // Calculate offsets
    let filename_start = 23;
    let filename_end = filename_start + filename_len;
    let salt_start = filename_end;
    let salt_end = salt_start + SALT_LENGTH;
    let nonce_start = salt_end;
    let nonce_end = nonce_start + NONCE_LENGTH;
    let ciphertext_start = nonce_end;

    // Validate file size
    if encrypted_data.len() < ciphertext_start + 16 {
        return Err(IronlockError::InvalidFileFormat);
    }

    // Extract components
    let filename_bytes = &encrypted_data[filename_start..filename_end];
    let original_filename =
        String::from_utf8(filename_bytes.to_vec()).map_err(|_| IronlockError::InvalidFileFormat)?;

    let salt: [u8; SALT_LENGTH] = encrypted_data[salt_start..salt_end]
        .try_into()
        .map_err(|_| IronlockError::InvalidFileFormat)?;

    let nonce: [u8; NONCE_LENGTH] = encrypted_data[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| IronlockError::InvalidFileFormat)?;

    let ciphertext = &encrypted_data[ciphertext_start..];

    // Derive key and decrypt with header as AAD
    let key = derive_key_from_password(password, &salt, &kdf_params)?;
    let aad = &encrypted_data[..ciphertext_start];
    let plaintext = decrypt(&key, &nonce, ciphertext, aad)?;

    Ok((original_filename, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kdf() -> KdfParams {
        KdfParams {
            memory_kib: MIN_ARGON2_MEMORY_KIB,
            iterations: MIN_ARGON2_ITERATIONS,
            parallelism: MIN_ARGON2_PARALLELISM,
        }
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    b'A'..=b'F' => byte - b'A' + 10,
                    _ => panic!("invalid hexadecimal test fixture"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    // ==================== Key Derivation Tests ====================

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password";
        let salt = [0u8; SALT_LENGTH];

        let key1 = derive_key_from_password(password, &salt, &KdfParams::current()).unwrap();
        let key2 = derive_key_from_password(password, &salt, &KdfParams::current()).unwrap();

        assert_eq!(
            *key1, *key2,
            "Same password and salt should produce same key"
        );
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = b"test_password";
        let salt1 = [0u8; SALT_LENGTH];
        let salt2 = [1u8; SALT_LENGTH];

        let key1 = derive_key_from_password(password, &salt1, &KdfParams::current()).unwrap();
        let key2 = derive_key_from_password(password, &salt2, &KdfParams::current()).unwrap();

        assert_ne!(
            *key1, *key2,
            "Different salts should produce different keys"
        );
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = [0u8; SALT_LENGTH];
        let key1 = derive_key_from_password(b"password1", &salt, &KdfParams::current()).unwrap();
        let key2 = derive_key_from_password(b"password2", &salt, &KdfParams::current()).unwrap();

        assert_ne!(
            *key1, *key2,
            "Different passwords should produce different keys"
        );
    }

    #[test]
    fn test_derive_key_empty_password() {
        let salt = [0u8; SALT_LENGTH];
        let result = derive_key_from_password(b"", &salt, &KdfParams::current());
        assert!(result.is_ok(), "Empty password should still derive a key");
    }

    #[test]
    fn test_derive_key_length() {
        let password = b"test";
        let salt = [0u8; SALT_LENGTH];
        let key = derive_key_from_password(password, &salt, &KdfParams::current()).unwrap();

        assert_eq!(
            key.len(),
            KEY_LENGTH,
            "Key should be exactly KEY_LENGTH bytes"
        );
    }

    // ==================== Salt & Nonce Generation Tests ====================

    #[test]
    fn test_generate_salt_length() {
        let salt = generate_salt();
        assert_eq!(salt.len(), SALT_LENGTH);
    }

    #[test]
    fn test_generate_salt_randomness() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2, "Generated salts should be unique");
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), NONCE_LENGTH);
    }

    #[test]
    fn test_generate_nonce_randomness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2, "Generated nonces should be unique");
    }

    // ==================== Low-Level Encrypt/Decrypt Tests ====================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(&key, &nonce, plaintext, &[]).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, &[]).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_output() {
        let key = [0u8; KEY_LENGTH];
        let nonce1 = [0u8; NONCE_LENGTH];
        let nonce2 = [1u8; NONCE_LENGTH];
        let plaintext = b"Hello, World!";

        let ciphertext1 = encrypt(&key, &nonce1, plaintext, &[]).unwrap();
        let ciphertext2 = encrypt(&key, &nonce2, plaintext, &[]).unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Different nonces should produce different ciphertext"
        );
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [0u8; KEY_LENGTH];
        let key2 = [1u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key1, &nonce, plaintext, &[]).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext, &[]);

        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce1 = [0u8; NONCE_LENGTH];
        let nonce2 = [1u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce1, plaintext, &[]).unwrap();
        let result = decrypt(&key, &nonce2, &ciphertext, &[]);

        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext, &[]).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, &[]).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_large_data() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB

        let ciphertext = encrypt(&key, &nonce, &plaintext, &[]).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, &[]).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_includes_auth_tag() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Hello";

        let ciphertext = encrypt(&key, &nonce, plaintext, &[]).unwrap();

        // ChaCha20-Poly1305 adds a 16-byte auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let mut ciphertext = encrypt(&key, &nonce, plaintext, &[]).unwrap();
        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext, &[]);
        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce, plaintext, &[]).unwrap();
        let truncated = &ciphertext[..ciphertext.len() - 1];

        let result = decrypt(&key, &nonce, truncated, &[]);
        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    // ==================== Low-Level AAD Tests ====================

    #[test]
    fn test_encrypt_decrypt_with_aad_roundtrip() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Hello, AAD!";
        let aad = b"authenticated header data";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aad_mismatch_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce, plaintext, b"correct aad").unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, b"wrong aad");

        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    #[test]
    fn test_missing_aad_on_decrypt_fails() {
        let key = [0u8; KEY_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce, plaintext, b"some aad").unwrap();
        // Decrypt with empty AAD when non-empty was used for encryption
        let result = decrypt(&key, &nonce, &ciphertext, &[]);

        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    // ==================== File Format Tests ====================

    #[test]
    fn test_encrypted_roundtrip() {
        let password = b"test_password_123";
        let plaintext = b"Hello, World! This is a secret message.";
        let filename = "test_encrypted_roundtrip.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        let plaintext = b"Secret data";
        let filename = "test_wrong_password_fails.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let result = decrypt_file(wrong_password, &encrypted);

        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let data = b"NOTLOCK\x01xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = decrypt_file(b"password", data);
        assert!(matches!(result, Err(IronlockError::InvalidFileFormat)));
    }

    #[test]
    fn test_file_too_small() {
        let data = b"IRONLOC";
        let result = decrypt_file(b"password", data);
        assert!(matches!(result, Err(IronlockError::InvalidFileFormat)));
    }

    #[test]
    fn test_invalid_version() {
        // Create valid header but with wrong version
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC_BYTES);
        data.push(99); // Invalid version
        data.extend_from_slice(&[0u8; 50]); // Padding

        let result = decrypt_file(b"password", &data);
        assert!(matches!(result, Err(IronlockError::InvalidFileFormat)));
    }

    #[test]
    fn test_empty_file_encryption() {
        let password = b"password";
        let plaintext = b"";
        let filename = "empty.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_unicode_filename() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "文件名_тест_🔐.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_long_filename() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "a".repeat(255);

        let encrypted = create_encrypted_file(password, &filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_file_with_spaces_in_name() {
        let password = b"password";
        let plaintext = b"content";
        let filename = "my secret file.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
    }

    #[test]
    fn test_binary_data_encryption() {
        let password = b"password";
        // Binary data with all byte values
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let filename = "binary.bin";

        let encrypted = create_encrypted_file(password, filename, &plaintext).unwrap();
        let (_, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_encrypted_file_structure() {
        let password = b"password";
        let plaintext = b"test";
        let filename = "test.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Verify magic bytes
        assert_eq!(&encrypted[0..8], MAGIC_BYTES);

        // Verify version
        assert_eq!(encrypted[8], FORMAT_VERSION);

        // Verify KDF params
        let kdf = KdfParams::current();
        let memory =
            u32::from_be_bytes([encrypted[9], encrypted[10], encrypted[11], encrypted[12]]);
        assert_eq!(memory, kdf.memory_kib);
        let iterations =
            u32::from_be_bytes([encrypted[13], encrypted[14], encrypted[15], encrypted[16]]);
        assert_eq!(iterations, kdf.iterations);
        let parallelism =
            u32::from_be_bytes([encrypted[17], encrypted[18], encrypted[19], encrypted[20]]);
        assert_eq!(parallelism, kdf.parallelism);

        // Verify filename length (big-endian u16)
        let filename_len = u16::from_be_bytes([encrypted[21], encrypted[22]]) as usize;
        assert_eq!(filename_len, filename.len());

        // Verify filename
        let stored_filename = std::str::from_utf8(&encrypted[23..23 + filename_len]).unwrap();
        assert_eq!(stored_filename, filename);
    }

    #[test]
    fn test_different_encryptions_produce_different_output() {
        let password = b"password";
        let plaintext = b"same data";
        let filename = "file.txt";

        let encrypted1 = create_encrypted_file(password, filename, plaintext).unwrap();
        let encrypted2 = create_encrypted_file(password, filename, plaintext).unwrap();

        // Due to random salt and nonce, outputs should differ
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_corrupted_salt_fails() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "test.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Corrupt the salt area (after magic + version + kdf(12) + filename_len(2) + filename)
        let salt_offset = 23 + filename.len();
        encrypted[salt_offset] ^= 0xFF;

        let result = decrypt_file(password, &encrypted);
        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    #[test]
    fn test_corrupted_nonce_fails() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "test.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Corrupt the nonce area (after salt)
        let nonce_offset = 23 + filename.len() + SALT_LENGTH;
        encrypted[nonce_offset] ^= 0xFF;

        let result = decrypt_file(password, &encrypted);
        assert!(matches!(result, Err(IronlockError::DecryptionFailed)));
    }

    #[test]
    fn test_special_characters_in_password() {
        let password = "pässwörd🔐!@#$%^&*()".as_bytes();
        let plaintext = b"secret";
        let filename = "file.txt";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (_, recovered) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_very_long_password() {
        let password = vec![b'a'; 10000];
        let plaintext = b"data";
        let filename = "file.txt";

        let encrypted = create_encrypted_file(&password, filename, plaintext).unwrap();
        let (_, recovered) = decrypt_file(&password, &encrypted).unwrap();

        assert_eq!(recovered, plaintext);
    }

    // ==================== Filename Boundary Tests ====================

    #[test]
    fn test_filename_at_u16_max_boundary() {
        let password = b"password";
        let plaintext = b"data";
        // Exactly 65535 bytes — the maximum the u16 length field can represent
        let filename = "a".repeat(u16::MAX as usize);

        let encrypted = create_encrypted_file(password, &filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_filename_exceeds_u16_max_fails() {
        let password = b"password";
        let plaintext = b"data";
        // 65536 bytes — one more than the u16 max
        let filename = "a".repeat(u16::MAX as usize + 1);

        let result = create_encrypted_file(password, &filename, plaintext);
        assert!(
            matches!(result, Err(IronlockError::EncryptionFailed(_))),
            "Filename exceeding u16::MAX bytes should fail"
        );
    }

    #[test]
    fn test_filename_length_field_lies_too_large() {
        // Craft a file where the filename length field claims more bytes than exist
        let password = b"password";
        let plaintext = b"data";
        let filename = "test.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Overwrite filename length with a huge value (offset 21)
        let fake_len: u16 = 60000;
        encrypted[21] = fake_len.to_be_bytes()[0];
        encrypted[22] = fake_len.to_be_bytes()[1];

        let result = decrypt_file(password, &encrypted);
        assert!(
            result.is_err(),
            "Lying filename length field should cause a parse error"
        );
    }

    #[test]
    fn test_non_utf8_filename_in_encrypted_data() {
        // Manually construct encrypted data with invalid UTF-8 in the filename field.
        // The AAD check will fail before UTF-8 validation, but the file should still
        // be rejected either way.
        let password = b"password";
        let kdf = KdfParams::current();
        let salt = [0u8; SALT_LENGTH];
        let nonce = [0u8; NONCE_LENGTH];

        let invalid_utf8_filename: &[u8] = &[0xFF, 0xFE, 0x80, 0x81];

        let mut header = Vec::new();
        header.extend_from_slice(MAGIC_BYTES);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&kdf.memory_kib.to_be_bytes());
        header.extend_from_slice(&kdf.iterations.to_be_bytes());
        header.extend_from_slice(&kdf.parallelism.to_be_bytes());
        header.extend_from_slice(&(invalid_utf8_filename.len() as u16).to_be_bytes());
        header.extend_from_slice(invalid_utf8_filename);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let key = derive_key_from_password(password, &salt, &kdf).unwrap();
        let ciphertext = encrypt(&key, &nonce, b"data", &header).unwrap();

        let mut data = header;
        data.extend_from_slice(&ciphertext);

        let result = decrypt_file(password, &data);
        // Decryption fails because the invalid UTF-8 filename in the header
        // was authenticated — parsing will reject it as InvalidFileFormat
        assert!(
            matches!(result, Err(IronlockError::InvalidFileFormat)),
            "Non-UTF-8 filename should return InvalidFileFormat"
        );
    }

    #[test]
    fn test_filename_with_path_separators() {
        // A filename containing slashes should round-trip at the crypto layer
        // (path traversal sanitization is handled in file_ops, not here)
        let password = b"password";
        let plaintext = b"data";
        let filename = "../../etc/passwd";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_empty_filename() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let (recovered_filename, _) = decrypt_file(password, &encrypted).unwrap();

        assert_eq!(recovered_filename, "");
    }

    // ==================== Double Encryption Test ====================

    #[test]
    fn test_double_encryption_roundtrip() {
        let password1 = b"first_password";
        let password2 = b"second_password";
        let plaintext = b"original content";
        let filename = "secret.txt";

        // First encryption
        let encrypted_once = create_encrypted_file(password1, filename, plaintext).unwrap();

        // Second encryption (encrypting the already-encrypted blob)
        let encrypted_twice =
            create_encrypted_file(password2, "secret.il", &encrypted_once).unwrap();

        // Decrypt outer layer
        let (outer_filename, inner_blob) = decrypt_file(password2, &encrypted_twice).unwrap();
        assert_eq!(outer_filename, "secret.il");

        // Decrypt inner layer
        let (inner_filename, recovered_plaintext) = decrypt_file(password1, &inner_blob).unwrap();
        assert_eq!(inner_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    // ==================== Truncation & Boundary Tests ====================

    #[test]
    fn test_file_exactly_minimum_size_but_invalid() {
        // Construct data that is exactly the minimum size (67 bytes for empty filename)
        // but has valid magic/version so it reaches the decrypt stage and fails.
        let min_size: usize = 8 + 1 + 12 + 2 + 16 + 12 + 16; // 67
        let mut data = vec![0u8; min_size];
        data[..8].copy_from_slice(MAGIC_BYTES);
        data[8] = FORMAT_VERSION;
        // KDF params and filename_len = 0 (already zeroed)

        let result = decrypt_file(b"password", &data);
        // Should fail at decryption (zero KDF params cause an Argon2 param error)
        assert!(
            result.is_err(),
            "Minimum-size file with valid header should fail"
        );
    }

    #[test]
    fn test_file_one_byte_below_minimum_size() {
        let min_size: usize = 8 + 1 + 12 + 2 + 16 + 12 + 16; // 67
        let mut data = vec![0u8; min_size - 1];
        data[..8].copy_from_slice(MAGIC_BYTES);
        data[8] = FORMAT_VERSION;

        let result = decrypt_file(b"password", &data);
        assert!(
            matches!(result, Err(IronlockError::InvalidFileFormat)),
            "File below minimum size should be rejected as invalid format"
        );
    }

    #[test]
    fn test_custom_kdf_params_roundtrip() {
        // Create an encrypted file with non-default KdfParams and verify decryption works
        let password = b"custom_kdf_password";
        let plaintext = b"Custom KDF params test data";
        let filename = "custom_kdf.txt";

        let custom_kdf = KdfParams {
            memory_kib: 32768, // 32 MiB instead of 64 MiB
            iterations: 2,     // 2 instead of 3
            parallelism: 2,    // 2 instead of 4
        };

        let encrypted =
            create_encrypted_file_with_params(password, filename, plaintext, &custom_kdf).unwrap();

        // Verify header stores the custom params
        let memory =
            u32::from_be_bytes([encrypted[9], encrypted[10], encrypted[11], encrypted[12]]);
        assert_eq!(memory, 32768);
        let iterations =
            u32::from_be_bytes([encrypted[13], encrypted[14], encrypted[15], encrypted[16]]);
        assert_eq!(iterations, 2);
        let parallelism =
            u32::from_be_bytes([encrypted[17], encrypted[18], encrypted[19], encrypted[20]]);
        assert_eq!(parallelism, 2);

        // Decrypt should read the params from the header and succeed
        let (recovered_filename, recovered_plaintext) = decrypt_file(password, &encrypted).unwrap();
        assert_eq!(recovered_filename, filename);
        assert_eq!(recovered_plaintext, plaintext);
    }

    #[test]
    fn test_encrypted_file_structure_detailed() {
        // Verify the exact header layout
        let password = b"password";
        let plaintext = b"structure test";
        let filename = "struct.dat";

        let encrypted = create_encrypted_file(password, filename, plaintext).unwrap();
        let kdf = KdfParams::current();

        // Magic bytes at offset 0..8
        assert_eq!(&encrypted[0..8], MAGIC_BYTES);

        // Version at offset 8
        assert_eq!(encrypted[8], FORMAT_VERSION);

        // KDF memory at offset 9..13
        assert_eq!(
            u32::from_be_bytes([encrypted[9], encrypted[10], encrypted[11], encrypted[12]]),
            kdf.memory_kib
        );

        // KDF iterations at offset 13..17
        assert_eq!(
            u32::from_be_bytes([encrypted[13], encrypted[14], encrypted[15], encrypted[16]]),
            kdf.iterations
        );

        // KDF parallelism at offset 17..21
        assert_eq!(
            u32::from_be_bytes([encrypted[17], encrypted[18], encrypted[19], encrypted[20]]),
            kdf.parallelism
        );

        // Filename length at offset 21..23
        let filename_len = u16::from_be_bytes([encrypted[21], encrypted[22]]) as usize;
        assert_eq!(filename_len, filename.len());

        // Filename at offset 23..23+N
        let stored_filename = std::str::from_utf8(&encrypted[23..23 + filename_len]).unwrap();
        assert_eq!(stored_filename, filename);

        // Salt at offset 23+N..39+N (16 bytes)
        let salt_start = 23 + filename_len;
        assert_eq!(
            encrypted[salt_start..salt_start + SALT_LENGTH].len(),
            SALT_LENGTH
        );

        // Nonce at offset 39+N..51+N (12 bytes)
        let nonce_start = salt_start + SALT_LENGTH;
        assert_eq!(
            encrypted[nonce_start..nonce_start + NONCE_LENGTH].len(),
            NONCE_LENGTH
        );

        // Ciphertext + auth tag at offset 51+N..end
        let ciphertext_start = nonce_start + NONCE_LENGTH;
        let ciphertext_len = encrypted.len() - ciphertext_start;
        // plaintext(14) + auth_tag(16) = 30
        assert_eq!(ciphertext_len, plaintext.len() + 16);
    }

    // ==================== Header Authentication Tests ====================

    #[test]
    fn test_tampered_filename_detected() {
        let password = b"password";
        let plaintext = b"secret data";
        let filename = "real.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Tamper with the filename in the header (offset 23: 'r' -> 'x')
        encrypted[23] = b'x';

        let result = decrypt_file(password, &encrypted);
        assert!(
            matches!(result, Err(IronlockError::DecryptionFailed)),
            "Tampered header filename should be detected via AAD"
        );
    }

    #[test]
    fn test_tampered_kdf_params_detected() {
        let password = b"password";
        let plaintext = b"secret data";
        let filename = "file.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Tamper with the KDF iterations param (offset 13..17)
        let tampered_iterations: u32 = 2;
        encrypted[13..17].copy_from_slice(&tampered_iterations.to_be_bytes());

        let result = decrypt_file(password, &encrypted);
        assert!(
            result.is_err(),
            "Tampered KDF params in header should be detected"
        );
    }

    #[test]
    fn test_tampered_version_byte_detected() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "file.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        // Change version — should fail because it no longer matches FORMAT_VERSION
        encrypted[8] = 99;

        let result = decrypt_file(password, &encrypted);
        assert!(
            matches!(result, Err(IronlockError::InvalidFileFormat)),
            "Invalid version byte should be rejected"
        );
    }

    #[test]
    fn test_tampered_magic_bytes_detected() {
        let password = b"password";
        let plaintext = b"data";
        let filename = "file.txt";

        let mut encrypted = create_encrypted_file(password, filename, plaintext).unwrap();

        encrypted[7] ^= 0xFF;

        let result = decrypt_file(password, &encrypted);
        assert!(
            matches!(result, Err(IronlockError::InvalidFileFormat)),
            "Tampered magic bytes should be rejected"
        );
    }

    #[test]
    fn test_current_kdf_profile_is_stable_and_valid() {
        assert_eq!(
            KdfParams::current(),
            KdfParams {
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 4,
            }
        );
        validate_kdf_params(&KdfParams::current()).unwrap();
    }

    #[test]
    fn test_kdf_parameter_boundaries_are_accepted() {
        let accepted = [
            test_kdf(),
            KdfParams {
                memory_kib: MIN_ARGON2_PARALLELISM * 8,
                iterations: MAX_ARGON2_ITERATIONS,
                parallelism: MIN_ARGON2_PARALLELISM,
            },
            KdfParams {
                memory_kib: MAX_ARGON2_PARALLELISM * 8,
                iterations: MIN_ARGON2_ITERATIONS,
                parallelism: MAX_ARGON2_PARALLELISM,
            },
            KdfParams {
                memory_kib: MAX_ARGON2_MEMORY_KIB,
                iterations: MAX_ARGON2_ITERATIONS,
                parallelism: MAX_ARGON2_PARALLELISM,
            },
        ];
        for params in accepted {
            validate_kdf_params(&params)
                .unwrap_or_else(|error| panic!("valid boundary {params:?} was rejected: {error}"));
        }
    }

    #[test]
    fn test_kdf_resource_limit_matrix() {
        let invalid = [
            KdfParams {
                memory_kib: MIN_ARGON2_MEMORY_KIB - 1,
                ..test_kdf()
            },
            KdfParams {
                memory_kib: MAX_ARGON2_MEMORY_KIB + 1,
                ..test_kdf()
            },
            KdfParams {
                iterations: MIN_ARGON2_ITERATIONS - 1,
                ..test_kdf()
            },
            KdfParams {
                iterations: MAX_ARGON2_ITERATIONS + 1,
                ..test_kdf()
            },
            KdfParams {
                parallelism: MIN_ARGON2_PARALLELISM - 1,
                ..test_kdf()
            },
            KdfParams {
                parallelism: MAX_ARGON2_PARALLELISM + 1,
                ..test_kdf()
            },
        ];
        for params in invalid {
            assert!(
                matches!(
                    validate_kdf_params(&params),
                    Err(IronlockError::ResourceLimit(_))
                ),
                "misclassified {params:?}"
            );
            assert!(matches!(
                derive_key_from_password(b"password", b"0123456789abcdef", &params),
                Err(IronlockError::ResourceLimit(_))
            ));
        }
    }

    #[test]
    fn test_kdf_rejects_insufficient_memory_for_lanes() {
        let params = KdfParams {
            memory_kib: 63,
            iterations: 1,
            parallelism: 8,
        };
        assert!(matches!(
            validate_kdf_params(&params),
            Err(IronlockError::InvalidFileFormat)
        ));
        assert!(matches!(
            derive_key_from_password(b"password", b"0123456789abcdef", &params),
            Err(IronlockError::InvalidFileFormat)
        ));

        validate_kdf_params(&KdfParams {
            memory_kib: 64,
            ..params
        })
        .unwrap();
    }

    #[test]
    fn test_argon2_salt_length_boundary() {
        assert!(matches!(
            derive_key_from_password(b"password", &[0u8; 7], &test_kdf()),
            Err(IronlockError::EncryptionFailed(_))
        ));
        assert!(derive_key_from_password(b"password", &[0u8; 8], &test_kdf()).is_ok());
    }

    #[test]
    fn test_argon2id_known_answer() {
        let key = derive_key_from_password(b"password", b"0123456789abcdef", &test_kdf()).unwrap();
        let expected: [u8; KEY_LENGTH] =
            decode_hex("771338d819573c67116b39e1788ae8e04b0eb0cf9dfbbfe2e6d746cf3e464fc7")
                .try_into()
                .unwrap();
        assert_eq!(*key, expected);
    }

    #[test]
    fn test_derived_key_keeps_stable_address_when_guard_moves() {
        let key = derive_key_from_password(b"password", b"0123456789abcdef", &test_kdf()).unwrap();
        let pointer = key.as_ptr();
        let expected = *key;

        let moved = key;

        assert_eq!(moved.as_ptr(), pointer);
        assert_eq!(*moved, expected);
    }

    #[test]
    fn test_chacha20_poly1305_rfc_8439_vector() {
        let key: [u8; KEY_LENGTH] =
            decode_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; NONCE_LENGTH] = decode_hex("070000004041424344454647").try_into().unwrap();
        let aad = decode_hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = decode_hex(concat!(
            "4c616469657320616e642047656e746c",
            "656d656e206f662074686520636c6173",
            "73206f66202739393a20496620492063",
            "6f756c64206f6666657220796f75206f",
            "6e6c79206f6e652074697020666f7220",
            "746865206675747572652c2073756e73",
            "637265656e20776f756c642062652069",
            "742e"
        ));
        let expected = decode_hex(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2",
            "a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b",
            "1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58",
            "fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b",
            "61161ae10b594f09e26a7e902ecbd0600691"
        ));

        let ciphertext = encrypt(&key, &nonce, &plaintext, &aad).unwrap();
        assert_eq!(ciphertext, expected);
        assert_eq!(decrypt(&key, &nonce, &expected, &aad).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_rejects_every_length_below_auth_tag() {
        let key = [0x11; KEY_LENGTH];
        let nonce = [0x22; NONCE_LENGTH];
        for length in 0..16 {
            assert!(matches!(
                decrypt(&key, &nonce, &vec![0; length], b"aad"),
                Err(IronlockError::DecryptionFailed)
            ));
        }
    }

    #[test]
    fn test_every_ciphertext_and_tag_byte_is_authenticated() {
        let key = [0x31; KEY_LENGTH];
        let nonce = [0x72; NONCE_LENGTH];
        let aad = b"authenticated context";
        let ciphertext = encrypt(&key, &nonce, b"secret payload", aad).unwrap();
        for index in 0..ciphertext.len() {
            let mut mutated = ciphertext.clone();
            mutated[index] ^= 1;
            assert!(matches!(
                decrypt(&key, &nonce, &mutated, aad),
                Err(IronlockError::DecryptionFailed)
            ));
        }
    }

    #[test]
    fn test_every_aad_byte_is_authenticated() {
        let key = [0x31; KEY_LENGTH];
        let nonce = [0x72; NONCE_LENGTH];
        let aad = b"authenticated context";
        let ciphertext = encrypt(&key, &nonce, b"secret payload", aad).unwrap();
        for index in 0..aad.len() {
            let mut mutated_aad = aad.to_vec();
            mutated_aad[index] ^= 1;
            assert!(matches!(
                decrypt(&key, &nonce, &ciphertext, &mutated_aad),
                Err(IronlockError::DecryptionFailed)
            ));
        }
    }

    #[test]
    fn test_v1_minimum_kdf_roundtrip_and_exact_size() {
        let filename = "x";
        let plaintext = b"";
        let encrypted =
            create_encrypted_file_with_params(b"password", filename, plaintext, &test_kdf())
                .unwrap();
        assert_eq!(encrypted.len(), 8 + 1 + 12 + 2 + 1 + 16 + 12 + 16);
        assert_eq!(
            decrypt_file(b"password", &encrypted).unwrap(),
            (filename.to_string(), plaintext.to_vec())
        );
    }

    #[test]
    fn test_v1_critical_truncation_matrix() {
        let filename = "file.bin";
        let encrypted =
            create_encrypted_file_with_params(b"password", filename, b"payload", &test_kdf())
                .unwrap();
        let ciphertext_start = 23 + filename.len() + SALT_LENGTH + NONCE_LENGTH;
        let lengths = [
            0,
            7,
            8,
            9,
            20,
            22,
            23,
            ciphertext_start - 1,
            ciphertext_start,
            ciphertext_start + 15,
            encrypted.len() - 1,
        ];
        for length in lengths {
            assert!(
                decrypt_file(b"password", &encrypted[..length]).is_err(),
                "accepted prefix length {length}"
            );
        }
    }

    #[test]
    fn test_v1_hostile_header_and_body_mutation_matrix() {
        let filename = "file.bin";
        let encrypted =
            create_encrypted_file_with_params(b"password", filename, b"payload", &test_kdf())
                .unwrap();
        let salt_start = 23 + filename.len();
        let nonce_start = salt_start + SALT_LENGTH;
        let ciphertext_start = nonce_start + NONCE_LENGTH;

        let mut mutations = Vec::new();
        for index in [
            0,
            7,
            8,
            12,
            16,
            20,
            21,
            22,
            23,
            salt_start,
            nonce_start,
            ciphertext_start,
        ] {
            let mut mutated = encrypted.clone();
            mutated[index] ^= 1;
            mutations.push(mutated);
        }
        let mut tampered_tag = encrypted.clone();
        *tampered_tag.last_mut().unwrap() ^= 1;
        mutations.push(tampered_tag);
        let mut appended = encrypted;
        appended.push(0);
        mutations.push(appended);

        for (index, mutated) in mutations.into_iter().enumerate() {
            assert!(
                decrypt_file(b"password", &mutated).is_err(),
                "accepted mutation {index}"
            );
        }
    }

    #[test]
    fn test_v1_untrusted_kdf_fields_have_stable_error_classes() {
        let encrypted =
            create_encrypted_file_with_params(b"password", "file.bin", b"payload", &test_kdf())
                .unwrap();
        for (range, value) in [
            (9..13, MAX_ARGON2_MEMORY_KIB + 1),
            (13..17, MAX_ARGON2_ITERATIONS + 1),
            (17..21, MAX_ARGON2_PARALLELISM + 1),
        ] {
            let mut mutated = encrypted.clone();
            mutated[range].copy_from_slice(&value.to_be_bytes());
            assert!(matches!(
                decrypt_file(b"password", &mutated),
                Err(IronlockError::ResourceLimit(_))
            ));
        }

        let mut insufficient_memory = encrypted;
        insufficient_memory[17..21].copy_from_slice(&2u32.to_be_bytes());
        assert!(matches!(
            decrypt_file(b"password", &insufficient_memory),
            Err(IronlockError::InvalidFileFormat)
        ));
    }

    #[test]
    fn test_v1_filename_length_mutation_matrix_never_panics_or_succeeds() {
        let encrypted =
            create_encrypted_file_with_params(b"password", "file.bin", b"payload", &test_kdf())
                .unwrap();
        for claimed_length in [0u16, 1, 7, 9, 255, u16::MAX] {
            if claimed_length == 8 {
                continue;
            }
            let mut mutated = encrypted.clone();
            mutated[21..23].copy_from_slice(&claimed_length.to_be_bytes());
            assert!(
                decrypt_file(b"password", &mutated).is_err(),
                "accepted filename length {claimed_length}"
            );
        }
    }
}
