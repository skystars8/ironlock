use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use crate::crypto::{
    decrypt, decrypt_file as decrypt_legacy_file, derive_key_from_password, encrypt,
    generate_nonce, generate_salt, KdfParams, KEY_LENGTH, MAGIC_BYTES, NONCE_LENGTH, SALT_LENGTH,
};
use crate::error::{IronlockError, Result};

/// Version 2 hides metadata and authenticates independently encrypted chunks.
pub const FORMAT_VERSION: u8 = 2;

pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
const MAX_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_FILENAME_BYTES: usize = u16::MAX as usize;
const MAX_LEGACY_FILE_SIZE: u64 = 256 * 1024 * 1024;

const HEADER_SIZE: usize = 8 + 1 + 12 + 4 + SALT_LENGTH + NONCE_LENGTH;
const RECORD_HEADER_SIZE: usize = 1 + 8 + 4;
const TAG_SIZE: usize = 16;

const RECORD_METADATA: u8 = 1;
const RECORD_DATA: u8 = 2;
const RECORD_FINAL: u8 = 3;
const FINAL_PLAINTEXT_SIZE: usize = 16;

fn invalid_format<T>() -> Result<T> {
    Err(IronlockError::InvalidFileFormat)
}

fn read_exact_format(reader: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    reader
        .read_exact(buffer)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => IronlockError::InvalidFileFormat,
            _ => IronlockError::IoError(error),
        })
}

fn next_read(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(IronlockError::IoError(error)),
            Ok(read) => return Ok(read),
        }
    }
}

fn derive_record_nonce(base_nonce: &[u8; NONCE_LENGTH], sequence: u64) -> [u8; NONCE_LENGTH] {
    let mut nonce = *base_nonce;
    for (slot, sequence_byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *slot ^= sequence_byte;
    }
    nonce
}

fn record_header(
    record_type: u8,
    sequence: u64,
    ciphertext_len: usize,
) -> Result<[u8; RECORD_HEADER_SIZE]> {
    let ciphertext_len = u32::try_from(ciphertext_len)
        .map_err(|_| IronlockError::ResourceLimit("encrypted record is too large".into()))?;
    let mut record = [0u8; RECORD_HEADER_SIZE];
    record[0] = record_type;
    record[1..9].copy_from_slice(&sequence.to_be_bytes());
    record[9..13].copy_from_slice(&ciphertext_len.to_be_bytes());
    Ok(record)
}

fn record_aad(header: &[u8], record: &[u8; RECORD_HEADER_SIZE]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + record.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(record);
    aad
}

fn write_record(
    writer: &mut impl Write,
    key: &[u8; KEY_LENGTH],
    base_nonce: &[u8; NONCE_LENGTH],
    header: &[u8],
    record_type: u8,
    sequence: u64,
    plaintext: &[u8],
) -> Result<()> {
    let encrypted_len = plaintext
        .len()
        .checked_add(TAG_SIZE)
        .ok_or_else(|| IronlockError::ResourceLimit("encrypted record length overflow".into()))?;
    let record = record_header(record_type, sequence, encrypted_len)?;
    let aad = record_aad(header, &record);
    let nonce = derive_record_nonce(base_nonce, sequence);
    let ciphertext = encrypt(key, &nonce, plaintext, &aad)?;

    writer.write_all(&record)?;
    writer.write_all(&ciphertext)?;
    Ok(())
}

fn parse_u32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| IronlockError::InvalidFileFormat)?,
    ))
}

fn parse_u64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| IronlockError::InvalidFileFormat)?,
    ))
}

/// Encrypts a stream in bounded chunks using the current KDF profile.
pub fn encrypt_stream(
    password: &[u8],
    original_filename: &str,
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<u64> {
    encrypt_stream_with_params(
        password,
        original_filename,
        reader,
        writer,
        &KdfParams::current(),
    )
}

pub fn encrypt_stream_with_params(
    password: &[u8],
    original_filename: &str,
    reader: &mut impl Read,
    writer: &mut impl Write,
    kdf_params: &KdfParams,
) -> Result<u64> {
    let filename_bytes = original_filename.as_bytes();
    let filename_len = u16::try_from(filename_bytes.len())
        .map_err(|_| IronlockError::EncryptionFailed("Filename exceeds 65535 bytes".to_string()))?;

    let salt = generate_salt();
    let base_nonce = generate_nonce();
    let key = derive_key_from_password(password, &salt, kdf_params)?;

    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(MAGIC_BYTES);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&kdf_params.memory_kib.to_be_bytes());
    header.extend_from_slice(&kdf_params.iterations.to_be_bytes());
    header.extend_from_slice(&kdf_params.parallelism.to_be_bytes());
    header.extend_from_slice(&(DEFAULT_CHUNK_SIZE as u32).to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&base_nonce);
    debug_assert_eq!(header.len(), HEADER_SIZE);
    writer.write_all(&header)?;

    let mut metadata = Zeroizing::new(Vec::with_capacity(2 + filename_bytes.len()));
    metadata.extend_from_slice(&filename_len.to_be_bytes());
    metadata.extend_from_slice(filename_bytes);
    write_record(
        writer,
        &key,
        &base_nonce,
        &header,
        RECORD_METADATA,
        0,
        &metadata,
    )?;

    let mut buffer = Zeroizing::new(vec![0u8; DEFAULT_CHUNK_SIZE]);
    let mut total_plaintext = 0u64;
    let mut chunk_count = 0u64;
    let mut sequence = 1u64;

    loop {
        let mut filled = 0usize;
        while filled < buffer.len() {
            let read = next_read(reader, &mut buffer[filled..])?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            break;
        }

        write_record(
            writer,
            &key,
            &base_nonce,
            &header,
            RECORD_DATA,
            sequence,
            &buffer[..filled],
        )?;
        total_plaintext = total_plaintext
            .checked_add(filled as u64)
            .ok_or_else(|| IronlockError::ResourceLimit("plaintext length overflow".into()))?;
        chunk_count = chunk_count
            .checked_add(1)
            .ok_or_else(|| IronlockError::ResourceLimit("chunk counter overflow".into()))?;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| IronlockError::ResourceLimit("record counter exhausted".into()))?;

        if filled < buffer.len() {
            break;
        }
    }

    let mut final_record = [0u8; FINAL_PLAINTEXT_SIZE];
    final_record[..8].copy_from_slice(&total_plaintext.to_be_bytes());
    final_record[8..].copy_from_slice(&chunk_count.to_be_bytes());
    write_record(
        writer,
        &key,
        &base_nonce,
        &header,
        RECORD_FINAL,
        sequence,
        &final_record,
    )?;
    Ok(total_plaintext)
}

struct V2State<R> {
    reader: R,
    key: Zeroizing<[u8; KEY_LENGTH]>,
    header: Vec<u8>,
    base_nonce: [u8; NONCE_LENGTH],
    chunk_size: usize,
    next_sequence: u64,
}

enum DecryptMode<R> {
    V2(V2State<R>),
    Legacy(Zeroizing<Vec<u8>>),
}

/// A staged decryptor exposes authenticated metadata before creating plaintext
/// output, while retaining bounded streaming state for the content records.
pub struct StreamDecryptor<R> {
    filename: String,
    mode: DecryptMode<R>,
}

impl<R: Read> StreamDecryptor<R> {
    pub fn new(mut reader: R, password: &[u8]) -> Result<Self> {
        let mut prefix = [0u8; 9];
        read_exact_format(&mut reader, &mut prefix)?;
        if &prefix[..8] != MAGIC_BYTES {
            return invalid_format();
        }

        match prefix[8] {
            FORMAT_VERSION => Self::new_v2(reader, password, prefix),
            crate::crypto::FORMAT_VERSION => Self::new_legacy(reader, password, prefix),
            _ => invalid_format(),
        }
    }

    fn new_v2(mut reader: R, password: &[u8], prefix: [u8; 9]) -> Result<Self> {
        let mut header = vec![0u8; HEADER_SIZE];
        header[..9].copy_from_slice(&prefix);
        read_exact_format(&mut reader, &mut header[9..])?;

        let kdf_params = KdfParams {
            memory_kib: parse_u32(&header[9..13])?,
            iterations: parse_u32(&header[13..17])?,
            parallelism: parse_u32(&header[17..21])?,
        };
        let chunk_size = parse_u32(&header[21..25])? as usize;
        if !(1024..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(IronlockError::ResourceLimit(format!(
                "chunk size must be between 1024 and {MAX_CHUNK_SIZE} bytes"
            )));
        }

        let salt: [u8; SALT_LENGTH] = header[25..41]
            .try_into()
            .map_err(|_| IronlockError::InvalidFileFormat)?;
        let base_nonce: [u8; NONCE_LENGTH] = header[41..53]
            .try_into()
            .map_err(|_| IronlockError::InvalidFileFormat)?;
        let key = derive_key_from_password(password, &salt, &kdf_params)?;

        let metadata = read_record(
            &mut reader,
            &key,
            &base_nonce,
            &header,
            0,
            Some(RECORD_METADATA),
            MAX_FILENAME_BYTES + 2,
        )?;
        if metadata.len() < 2 {
            return invalid_format();
        }
        let filename_len = u16::from_be_bytes([metadata[0], metadata[1]]) as usize;
        if metadata.len() != filename_len + 2 {
            return invalid_format();
        }
        let filename = String::from_utf8(metadata[2..].to_vec())
            .map_err(|_| IronlockError::InvalidFileFormat)?;
        if filename.is_empty() {
            return invalid_format();
        }

        Ok(Self {
            filename,
            mode: DecryptMode::V2(V2State {
                reader,
                key,
                header,
                base_nonce,
                chunk_size,
                next_sequence: 1,
            }),
        })
    }

    fn new_legacy(reader: R, password: &[u8], prefix: [u8; 9]) -> Result<Self> {
        let mut encrypted = Zeroizing::new(Vec::new());
        encrypted.extend_from_slice(&prefix);
        let remaining_limit = MAX_LEGACY_FILE_SIZE
            .saturating_add(1)
            .saturating_sub(prefix.len() as u64);
        reader.take(remaining_limit).read_to_end(&mut encrypted)?;
        if encrypted.len() as u64 > MAX_LEGACY_FILE_SIZE {
            return Err(IronlockError::ResourceLimit(format!(
                "legacy encrypted files are limited to {MAX_LEGACY_FILE_SIZE} bytes"
            )));
        }

        let (filename, plaintext) = decrypt_legacy_file(password, &encrypted)?;
        Ok(Self {
            filename,
            mode: DecryptMode::Legacy(Zeroizing::new(plaintext)),
        })
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn decrypt_to(mut self, writer: &mut impl Write) -> Result<u64> {
        match &mut self.mode {
            DecryptMode::Legacy(plaintext) => {
                writer.write_all(plaintext)?;
                Ok(plaintext.len() as u64)
            }
            DecryptMode::V2(state) => {
                let mut total_plaintext = 0u64;
                let mut chunk_count = 0u64;

                loop {
                    let (record_type, plaintext) = read_next_record(state)?;
                    match record_type {
                        RECORD_DATA => {
                            if plaintext.is_empty() {
                                return invalid_format();
                            }
                            writer.write_all(&plaintext)?;
                            total_plaintext = total_plaintext
                                .checked_add(plaintext.len() as u64)
                                .ok_or_else(|| {
                                IronlockError::ResourceLimit("plaintext length overflow".into())
                            })?;
                            chunk_count = chunk_count.checked_add(1).ok_or_else(|| {
                                IronlockError::ResourceLimit("chunk counter overflow".into())
                            })?;
                        }
                        RECORD_FINAL => {
                            if plaintext.len() != FINAL_PLAINTEXT_SIZE {
                                return invalid_format();
                            }
                            let claimed_len = parse_u64(&plaintext[..8])?;
                            let claimed_chunks = parse_u64(&plaintext[8..])?;
                            if claimed_len != total_plaintext || claimed_chunks != chunk_count {
                                return Err(IronlockError::DecryptionFailed);
                            }

                            let mut trailing = [0u8; 1];
                            if next_read(&mut state.reader, &mut trailing)? != 0 {
                                return invalid_format();
                            }
                            return Ok(total_plaintext);
                        }
                        _ => return invalid_format(),
                    }
                }
            }
        }
    }
}

fn read_next_record<R: Read>(state: &mut V2State<R>) -> Result<(u8, Zeroizing<Vec<u8>>)> {
    let mut record = [0u8; RECORD_HEADER_SIZE];
    read_exact_format(&mut state.reader, &mut record)?;

    let record_type = record[0];
    let sequence = parse_u64(&record[1..9])?;
    if sequence != state.next_sequence {
        return Err(IronlockError::DecryptionFailed);
    }

    let max_plaintext = match record_type {
        RECORD_DATA => state.chunk_size,
        RECORD_FINAL => FINAL_PLAINTEXT_SIZE,
        _ => return invalid_format(),
    };
    let plaintext = decrypt_record_body(
        &mut state.reader,
        &state.key,
        &state.base_nonce,
        &state.header,
        &record,
        sequence,
        max_plaintext,
    )?;
    state.next_sequence = state
        .next_sequence
        .checked_add(1)
        .ok_or_else(|| IronlockError::ResourceLimit("record counter exhausted".into()))?;
    Ok((record_type, plaintext))
}

fn read_record(
    reader: &mut impl Read,
    key: &[u8; KEY_LENGTH],
    base_nonce: &[u8; NONCE_LENGTH],
    header: &[u8],
    expected_sequence: u64,
    expected_type: Option<u8>,
    max_plaintext: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut record = [0u8; RECORD_HEADER_SIZE];
    read_exact_format(reader, &mut record)?;

    if expected_type.is_some_and(|expected| record[0] != expected) {
        return Err(IronlockError::DecryptionFailed);
    }
    let sequence = parse_u64(&record[1..9])?;
    if sequence != expected_sequence {
        return Err(IronlockError::DecryptionFailed);
    }
    decrypt_record_body(
        reader,
        key,
        base_nonce,
        header,
        &record,
        sequence,
        max_plaintext,
    )
}

fn decrypt_record_body(
    reader: &mut impl Read,
    key: &[u8; KEY_LENGTH],
    base_nonce: &[u8; NONCE_LENGTH],
    header: &[u8],
    record: &[u8; RECORD_HEADER_SIZE],
    sequence: u64,
    max_plaintext: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let ciphertext_len = parse_u32(&record[9..13])? as usize;
    if ciphertext_len < TAG_SIZE
        || ciphertext_len
            .checked_sub(TAG_SIZE)
            .is_none_or(|plaintext_len| plaintext_len > max_plaintext)
    {
        return Err(IronlockError::ResourceLimit(
            "encrypted record exceeds the format limit".into(),
        ));
    }

    let mut ciphertext = vec![0u8; ciphertext_len];
    read_exact_format(reader, &mut ciphertext)?;
    let aad = record_aad(header, record);
    let nonce = derive_record_nonce(base_nonce, sequence);
    Ok(Zeroizing::new(decrypt(key, &nonce, &ciphertext, &aad)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn streaming_roundtrip_hides_filename_and_handles_multiple_chunks() {
        let password = b"correct horse battery staple";
        let filename = "medical-records.pdf";
        let plaintext = vec![0xA5; DEFAULT_CHUNK_SIZE * 2 + 123];

        let mut encrypted = Vec::new();
        let written = encrypt_stream(
            password,
            filename,
            &mut Cursor::new(&plaintext),
            &mut encrypted,
        )
        .unwrap();
        assert_eq!(written, plaintext.len() as u64);
        assert_eq!(encrypted[8], FORMAT_VERSION);
        assert!(!encrypted
            .windows(filename.len())
            .any(|window| window == filename.as_bytes()));

        let decryptor = StreamDecryptor::new(Cursor::new(&encrypted), password).unwrap();
        assert_eq!(decryptor.filename(), filename);
        let mut recovered = Vec::new();
        let recovered_len = decryptor.decrypt_to(&mut recovered).unwrap();
        assert_eq!(recovered_len, plaintext.len() as u64);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn truncation_and_trailing_data_are_rejected() {
        let mut encrypted = Vec::new();
        encrypt_stream(
            b"password",
            "file.bin",
            &mut Cursor::new(b"payload"),
            &mut encrypted,
        )
        .unwrap();

        let truncated = &encrypted[..encrypted.len() - 1];
        let decryptor = StreamDecryptor::new(Cursor::new(truncated), b"password").unwrap();
        assert!(decryptor.decrypt_to(&mut Vec::new()).is_err());

        encrypted.push(0);
        let decryptor = StreamDecryptor::new(Cursor::new(&encrypted), b"password").unwrap();
        assert!(decryptor.decrypt_to(&mut Vec::new()).is_err());
    }

    #[test]
    fn oversized_record_is_rejected_before_allocation() {
        let mut encrypted = Vec::new();
        encrypt_stream(
            b"password",
            "file.bin",
            &mut Cursor::new(b"payload"),
            &mut encrypted,
        )
        .unwrap();

        let metadata_record_len_offset = HEADER_SIZE + 9;
        encrypted[metadata_record_len_offset..metadata_record_len_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        let result = StreamDecryptor::new(Cursor::new(&encrypted), b"password");
        assert!(matches!(result, Err(IronlockError::ResourceLimit(_))));
    }

    #[test]
    fn legacy_v1_files_still_decrypt() {
        let legacy =
            crate::crypto::create_encrypted_file(b"password", "legacy.txt", b"legacy payload")
                .unwrap();
        let decryptor = StreamDecryptor::new(Cursor::new(legacy), b"password").unwrap();
        assert_eq!(decryptor.filename(), "legacy.txt");
        let mut plaintext = Vec::new();
        decryptor.decrypt_to(&mut plaintext).unwrap();
        assert_eq!(plaintext, b"legacy payload");
    }
}
