use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use crate::crypto::{
    decrypt, decrypt_file as decrypt_legacy_file, derive_key_from_password, encrypt,
    generate_nonce, generate_salt, KdfParams, LockedKey, KEY_LENGTH, MAGIC_BYTES, NONCE_LENGTH,
    SALT_LENGTH,
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
    if filename_bytes.is_empty() {
        return Err(IronlockError::EncryptionFailed(
            "Filename cannot be empty".to_string(),
        ));
    }
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
    key: LockedKey,
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
    use std::io::{Cursor, Error, ErrorKind};

    const TEST_PASSWORD: &[u8] = b"test password";

    fn test_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn encrypted_fixture(filename: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut encrypted = Vec::new();
        encrypt_stream_with_params(
            TEST_PASSWORD,
            filename,
            &mut Cursor::new(plaintext),
            &mut encrypted,
            &test_kdf(),
        )
        .unwrap();
        encrypted
    }

    fn decrypt_fixture(encrypted: &[u8]) -> Result<(String, Vec<u8>)> {
        let decryptor = StreamDecryptor::new(Cursor::new(encrypted), TEST_PASSWORD)?;
        let filename = decryptor.filename().to_string();
        let mut plaintext = Vec::new();
        decryptor.decrypt_to(&mut plaintext)?;
        Ok((filename, plaintext))
    }

    fn encoded_filename(filename: &str) -> Vec<u8> {
        let mut metadata = Vec::with_capacity(2 + filename.len());
        metadata.extend_from_slice(&(filename.len() as u16).to_be_bytes());
        metadata.extend_from_slice(filename.as_bytes());
        metadata
    }

    fn build_authenticated_stream(
        chunk_size: u32,
        metadata: &[u8],
        records: &[(u8, u64, Vec<u8>)],
    ) -> Vec<u8> {
        let kdf = test_kdf();
        let salt = [0x31; SALT_LENGTH];
        let base_nonce = [0x72; NONCE_LENGTH];
        let key = derive_key_from_password(TEST_PASSWORD, &salt, &kdf).unwrap();

        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.extend_from_slice(MAGIC_BYTES);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&kdf.memory_kib.to_be_bytes());
        header.extend_from_slice(&kdf.iterations.to_be_bytes());
        header.extend_from_slice(&kdf.parallelism.to_be_bytes());
        header.extend_from_slice(&chunk_size.to_be_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&base_nonce);
        assert_eq!(header.len(), HEADER_SIZE);

        let mut encrypted = header.clone();
        write_record(
            &mut encrypted,
            &key,
            &base_nonce,
            &header,
            RECORD_METADATA,
            0,
            metadata,
        )
        .unwrap();
        for (record_type, sequence, plaintext) in records {
            write_record(
                &mut encrypted,
                &key,
                &base_nonce,
                &header,
                *record_type,
                *sequence,
                plaintext,
            )
            .unwrap();
        }
        encrypted
    }

    fn deterministic_fixture(filename: &str, chunks: &[&[u8]]) -> Vec<u8> {
        let total_len = chunks.iter().map(|chunk| chunk.len() as u64).sum::<u64>();
        let mut final_plaintext = vec![0u8; FINAL_PLAINTEXT_SIZE];
        final_plaintext[..8].copy_from_slice(&total_len.to_be_bytes());
        final_plaintext[8..].copy_from_slice(&(chunks.len() as u64).to_be_bytes());

        let mut records = Vec::with_capacity(chunks.len() + 1);
        for (index, chunk) in chunks.iter().enumerate() {
            records.push((RECORD_DATA, index as u64 + 1, chunk.to_vec()));
        }
        records.push((RECORD_FINAL, chunks.len() as u64 + 1, final_plaintext));
        build_authenticated_stream(
            DEFAULT_CHUNK_SIZE as u32,
            &encoded_filename(filename),
            &records,
        )
    }

    fn record_offsets(encrypted: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut offset = HEADER_SIZE;
        while offset + RECORD_HEADER_SIZE <= encrypted.len() {
            offsets.push(offset);
            let ciphertext_len =
                u32::from_be_bytes(encrypted[offset + 9..offset + 13].try_into().unwrap()) as usize;
            offset += RECORD_HEADER_SIZE + ciphertext_len;
        }
        assert_eq!(offset, encrypted.len());
        offsets
    }

    struct FragmentedReader<R> {
        inner: R,
        max_read: usize,
    }

    impl<R: Read> Read for FragmentedReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(self.max_read);
            self.inner.read(&mut buffer[..limit])
        }
    }

    struct InterruptOnce<R> {
        inner: R,
        interrupted: bool,
    }

    impl<R: Read> Read for InterruptOnce<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(Error::new(ErrorKind::Interrupted, "try again"));
            }
            self.inner.read(buffer)
        }
    }

    #[derive(Default)]
    struct FragmentedWriter {
        bytes: Vec<u8>,
        max_write: usize,
    }

    impl Write for FragmentedWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let written = buffer.len().min(self.max_write);
            self.bytes.extend_from_slice(&buffer[..written]);
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingWriter {
        remaining: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(Error::new(ErrorKind::BrokenPipe, "injected failure"));
            }
            let written = buffer.len().min(self.remaining);
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

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

    #[test]
    fn record_nonce_derivation_is_stable_and_unique() {
        let base = [0xA5; NONCE_LENGTH];
        assert_eq!(derive_record_nonce(&base, 0), base);

        let mut expected_one = base;
        expected_one[NONCE_LENGTH - 1] ^= 1;
        assert_eq!(derive_record_nonce(&base, 1), expected_one);

        let mut expected_max = base;
        for byte in &mut expected_max[4..] {
            *byte ^= 0xFF;
        }
        assert_eq!(derive_record_nonce(&base, u64::MAX), expected_max);

        let sequences = [0, 1, 2, 255, 256, u32::MAX as u64, u64::MAX];
        let nonces: Vec<_> = sequences
            .iter()
            .map(|sequence| derive_record_nonce(&base, *sequence))
            .collect();
        for left in 0..nonces.len() {
            for right in left + 1..nonces.len() {
                assert_ne!(nonces[left], nonces[right]);
            }
        }
    }

    #[test]
    fn record_header_and_integer_parsers_use_big_endian() {
        let header = record_header(0xA7, 0x0102_0304_0506_0708, 0x1122_3344).unwrap();
        assert_eq!(header[0], 0xA7);
        assert_eq!(&header[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&header[9..13], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(parse_u32(&header[9..13]).unwrap(), 0x1122_3344);
        assert_eq!(parse_u64(&header[1..9]).unwrap(), 0x0102_0304_0506_0708);

        assert!(matches!(
            parse_u32(&[0; 3]),
            Err(IronlockError::InvalidFileFormat)
        ));
        assert!(matches!(
            parse_u64(&[0; 9]),
            Err(IronlockError::InvalidFileFormat)
        ));

        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            record_header(RECORD_DATA, 1, u32::MAX as usize + 1),
            Err(IronlockError::ResourceLimit(_))
        ));
    }

    #[test]
    fn read_helpers_retry_interrupts_and_classify_errors() {
        let mut interrupted = InterruptOnce {
            inner: Cursor::new(b"abc"),
            interrupted: false,
        };
        let mut buffer = [0u8; 3];
        assert_eq!(next_read(&mut interrupted, &mut buffer).unwrap(), 3);
        assert_eq!(&buffer, b"abc");

        let mut short = Cursor::new(b"x");
        assert!(matches!(
            read_exact_format(&mut short, &mut [0u8; 2]),
            Err(IronlockError::InvalidFileFormat)
        ));

        struct DeniedReader;
        impl Read for DeniedReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(Error::new(ErrorKind::PermissionDenied, "denied"))
            }
        }
        assert!(matches!(
            read_exact_format(&mut DeniedReader, &mut [0u8; 1]),
            Err(IronlockError::IoError(error)) if error.kind() == ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn stream_roundtrips_chunk_boundaries_and_empty_content() {
        for size in [
            0,
            1,
            DEFAULT_CHUNK_SIZE - 1,
            DEFAULT_CHUNK_SIZE,
            DEFAULT_CHUNK_SIZE + 1,
            DEFAULT_CHUNK_SIZE * 2,
        ] {
            let plaintext: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
            let encrypted = encrypted_fixture("boundary.bin", &plaintext);
            let (filename, recovered) = decrypt_fixture(&encrypted).unwrap();
            assert_eq!(filename, "boundary.bin", "size {size}");
            assert_eq!(recovered, plaintext, "size {size}");

            let expected_data_records = size.div_ceil(DEFAULT_CHUNK_SIZE);
            assert_eq!(record_offsets(&encrypted).len(), expected_data_records + 2);
        }
    }

    #[test]
    fn stream_header_and_record_layout_are_exact() {
        let filename = "layout.bin";
        let plaintext = b"payload";
        let encrypted = encrypted_fixture(filename, plaintext);

        assert_eq!(&encrypted[..8], MAGIC_BYTES);
        assert_eq!(encrypted[8], FORMAT_VERSION);
        assert_eq!(parse_u32(&encrypted[9..13]).unwrap(), 8);
        assert_eq!(parse_u32(&encrypted[13..17]).unwrap(), 1);
        assert_eq!(parse_u32(&encrypted[17..21]).unwrap(), 1);
        assert_eq!(
            parse_u32(&encrypted[21..25]).unwrap(),
            DEFAULT_CHUNK_SIZE as u32
        );

        let offsets = record_offsets(&encrypted);
        assert_eq!(offsets.len(), 3);
        assert_eq!(encrypted[offsets[0]], RECORD_METADATA);
        assert_eq!(
            parse_u64(&encrypted[offsets[0] + 1..offsets[0] + 9]).unwrap(),
            0
        );
        assert_eq!(
            parse_u32(&encrypted[offsets[0] + 9..offsets[0] + 13]).unwrap() as usize,
            2 + filename.len() + TAG_SIZE
        );
        assert_eq!(encrypted[offsets[1]], RECORD_DATA);
        assert_eq!(
            parse_u64(&encrypted[offsets[1] + 1..offsets[1] + 9]).unwrap(),
            1
        );
        assert_eq!(
            parse_u32(&encrypted[offsets[1] + 9..offsets[1] + 13]).unwrap() as usize,
            plaintext.len() + TAG_SIZE
        );
        assert_eq!(encrypted[offsets[2]], RECORD_FINAL);
        assert_eq!(
            parse_u64(&encrypted[offsets[2] + 1..offsets[2] + 9]).unwrap(),
            2
        );
        assert_eq!(
            parse_u32(&encrypted[offsets[2] + 9..offsets[2] + 13]).unwrap() as usize,
            FINAL_PLAINTEXT_SIZE + TAG_SIZE
        );
    }

    #[test]
    fn fragmented_and_interrupted_io_roundtrips() {
        let plaintext: Vec<u8> = (0..DEFAULT_CHUNK_SIZE + 37)
            .map(|index| (index % 239) as u8)
            .collect();
        let mut reader = InterruptOnce {
            inner: FragmentedReader {
                inner: Cursor::new(&plaintext),
                max_read: 3,
            },
            interrupted: false,
        };
        let mut encrypted_writer = FragmentedWriter {
            bytes: Vec::new(),
            max_write: 2,
        };
        let written = encrypt_stream_with_params(
            TEST_PASSWORD,
            "fragmented.bin",
            &mut reader,
            &mut encrypted_writer,
            &test_kdf(),
        )
        .unwrap();
        assert_eq!(written, plaintext.len() as u64);

        let encrypted_reader = FragmentedReader {
            inner: InterruptOnce {
                inner: Cursor::new(&encrypted_writer.bytes),
                interrupted: false,
            },
            max_read: 1,
        };
        let decryptor = StreamDecryptor::new(encrypted_reader, TEST_PASSWORD).unwrap();
        assert_eq!(decryptor.filename(), "fragmented.bin");
        let mut plaintext_writer = FragmentedWriter {
            bytes: Vec::new(),
            max_write: 5,
        };
        assert_eq!(
            decryptor.decrypt_to(&mut plaintext_writer).unwrap(),
            plaintext.len() as u64
        );
        assert_eq!(plaintext_writer.bytes, plaintext);
    }

    #[test]
    fn invalid_filenames_are_rejected_before_writing() {
        for filename in [String::new(), "a".repeat(u16::MAX as usize + 1)] {
            let mut output = Vec::new();
            let result = encrypt_stream_with_params(
                TEST_PASSWORD,
                &filename,
                &mut Cursor::new(b"payload"),
                &mut output,
                &test_kdf(),
            );
            assert!(matches!(result, Err(IronlockError::EncryptionFailed(_))));
            assert!(output.is_empty());
        }
    }

    #[test]
    fn maximum_and_unicode_filenames_roundtrip() {
        for filename in ["a".repeat(u16::MAX as usize), "秘密-🔐.bin".to_string()] {
            let encrypted = encrypted_fixture(&filename, b"payload");
            let (recovered_filename, plaintext) = decrypt_fixture(&encrypted).unwrap();
            assert_eq!(recovered_filename, filename);
            assert_eq!(plaintext, b"payload");
        }
    }

    #[test]
    fn invalid_kdf_parameters_are_rejected_before_writing() {
        let invalid = [
            KdfParams {
                memory_kib: 7,
                iterations: 1,
                parallelism: 1,
            },
            KdfParams {
                memory_kib: 8,
                iterations: 0,
                parallelism: 1,
            },
            KdfParams {
                memory_kib: 8,
                iterations: 1,
                parallelism: 2,
            },
        ];

        for kdf in invalid {
            let mut output = Vec::new();
            let result = encrypt_stream_with_params(
                TEST_PASSWORD,
                "file.bin",
                &mut Cursor::new(b"payload"),
                &mut output,
                &kdf,
            );
            assert!(result.is_err(), "accepted {kdf:?}");
            assert!(output.is_empty(), "wrote output for {kdf:?}");
        }
    }

    #[test]
    fn wrong_password_is_rejected_before_metadata_is_exposed() {
        let encrypted = encrypted_fixture("private-name.txt", b"payload");
        assert!(matches!(
            StreamDecryptor::new(Cursor::new(encrypted), b"wrong password"),
            Err(IronlockError::DecryptionFailed)
        ));
    }

    #[test]
    fn prefix_magic_version_and_header_truncations_are_invalid_format() {
        let encrypted = deterministic_fixture("file.bin", &[b"payload"]);
        for length in 0..HEADER_SIZE {
            let result = StreamDecryptor::new(Cursor::new(&encrypted[..length]), TEST_PASSWORD);
            assert!(
                matches!(result, Err(IronlockError::InvalidFileFormat)),
                "accepted or misclassified prefix length {length}"
            );
        }

        let mut bad_magic = encrypted.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            StreamDecryptor::new(Cursor::new(bad_magic), TEST_PASSWORD),
            Err(IronlockError::InvalidFileFormat)
        ));

        let mut bad_version = encrypted;
        bad_version[8] = 99;
        assert!(matches!(
            StreamDecryptor::new(Cursor::new(bad_version), TEST_PASSWORD),
            Err(IronlockError::InvalidFileFormat)
        ));
    }

    #[test]
    fn header_resource_limits_are_enforced_before_key_derivation() {
        let encrypted = deterministic_fixture("file.bin", &[]);
        let cases = [
            (9..13, 7u32),
            (13..17, 0u32),
            (17..21, 0u32),
            (21..25, 1023u32),
            (21..25, MAX_CHUNK_SIZE as u32 + 1),
        ];
        for (range, value) in cases {
            let mut mutated = encrypted.clone();
            mutated[range].copy_from_slice(&value.to_be_bytes());
            assert!(matches!(
                StreamDecryptor::new(Cursor::new(mutated), TEST_PASSWORD),
                Err(IronlockError::ResourceLimit(_))
            ));
        }

        let mut insufficient_memory = encrypted;
        insufficient_memory[17..21].copy_from_slice(&2u32.to_be_bytes());
        assert!(matches!(
            StreamDecryptor::new(Cursor::new(insufficient_memory), TEST_PASSWORD),
            Err(IronlockError::InvalidFileFormat)
        ));
    }

    #[test]
    fn authenticated_header_fields_cannot_be_changed() {
        let encrypted = deterministic_fixture("file.bin", &[b"payload"]);
        for (offset, replacement) in [(16, 2u8), (25, 0x30), (41, 0x73)] {
            let mut mutated = encrypted.clone();
            mutated[offset] = replacement;
            assert!(matches!(
                StreamDecryptor::new(Cursor::new(mutated), TEST_PASSWORD),
                Err(IronlockError::DecryptionFailed)
            ));
        }

        let mut valid_but_changed_chunk_size = encrypted;
        valid_but_changed_chunk_size[21..25].copy_from_slice(&32768u32.to_be_bytes());
        assert!(matches!(
            StreamDecryptor::new(Cursor::new(valid_but_changed_chunk_size), TEST_PASSWORD),
            Err(IronlockError::DecryptionFailed)
        ));
    }

    #[test]
    fn metadata_record_header_mutations_have_stable_errors() {
        let encrypted = deterministic_fixture("file.bin", &[b"payload"]);
        let metadata_offset = HEADER_SIZE;

        let mut wrong_type = encrypted.clone();
        wrong_type[metadata_offset] = RECORD_DATA;
        assert!(matches!(
            StreamDecryptor::new(Cursor::new(wrong_type), TEST_PASSWORD),
            Err(IronlockError::DecryptionFailed)
        ));

        let mut wrong_sequence = encrypted.clone();
        wrong_sequence[metadata_offset + 1..metadata_offset + 9]
            .copy_from_slice(&1u64.to_be_bytes());
        assert!(matches!(
            StreamDecryptor::new(Cursor::new(wrong_sequence), TEST_PASSWORD),
            Err(IronlockError::DecryptionFailed)
        ));

        for ciphertext_len in [
            (TAG_SIZE - 1) as u32,
            (MAX_FILENAME_BYTES + 2 + TAG_SIZE + 1) as u32,
        ] {
            let mut invalid_length = encrypted.clone();
            invalid_length[metadata_offset + 9..metadata_offset + 13]
                .copy_from_slice(&ciphertext_len.to_be_bytes());
            assert!(matches!(
                StreamDecryptor::new(Cursor::new(invalid_length), TEST_PASSWORD),
                Err(IronlockError::ResourceLimit(_))
            ));
        }
    }

    #[test]
    fn metadata_ciphertext_and_tag_tampering_are_rejected() {
        let encrypted = deterministic_fixture("private.txt", &[b"payload"]);
        let metadata_offset = HEADER_SIZE;
        let metadata_len =
            parse_u32(&encrypted[metadata_offset + 9..metadata_offset + RECORD_HEADER_SIZE])
                .unwrap() as usize;
        for ciphertext_index in [0, metadata_len - 1] {
            let mut mutated = encrypted.clone();
            mutated[metadata_offset + RECORD_HEADER_SIZE + ciphertext_index] ^= 1;
            assert!(matches!(
                StreamDecryptor::new(Cursor::new(mutated), TEST_PASSWORD),
                Err(IronlockError::DecryptionFailed)
            ));
        }
    }

    #[test]
    fn authenticated_malformed_metadata_is_rejected() {
        let malformed = [
            Vec::new(),
            vec![0],
            vec![0, 0],
            vec![0, 1],
            vec![0, 2, b'a'],
            vec![0, 1, 0xFF],
        ];
        for metadata in malformed {
            let encrypted = build_authenticated_stream(
                DEFAULT_CHUNK_SIZE as u32,
                &metadata,
                &[(RECORD_FINAL, 1, vec![0; FINAL_PLAINTEXT_SIZE])],
            );
            assert!(matches!(
                StreamDecryptor::new(Cursor::new(encrypted), TEST_PASSWORD),
                Err(IronlockError::InvalidFileFormat)
            ));
        }
    }

    #[test]
    fn data_record_header_and_body_mutations_are_rejected() {
        let encrypted = deterministic_fixture("file.bin", &[b"payload"]);
        let offsets = record_offsets(&encrypted);
        let data_offset = offsets[1];

        let mut wrong_type = encrypted.clone();
        wrong_type[data_offset] = 0xFF;
        let decryptor = StreamDecryptor::new(Cursor::new(wrong_type), TEST_PASSWORD).unwrap();
        assert!(matches!(
            decryptor.decrypt_to(&mut Vec::new()),
            Err(IronlockError::InvalidFileFormat)
        ));

        let mut wrong_sequence = encrypted.clone();
        wrong_sequence[data_offset + 1..data_offset + 9].copy_from_slice(&2u64.to_be_bytes());
        let decryptor = StreamDecryptor::new(Cursor::new(wrong_sequence), TEST_PASSWORD).unwrap();
        assert!(matches!(
            decryptor.decrypt_to(&mut Vec::new()),
            Err(IronlockError::DecryptionFailed)
        ));

        for ciphertext_len in [
            (TAG_SIZE - 1) as u32,
            (DEFAULT_CHUNK_SIZE + TAG_SIZE + 1) as u32,
        ] {
            let mut invalid_length = encrypted.clone();
            invalid_length[data_offset + 9..data_offset + 13]
                .copy_from_slice(&ciphertext_len.to_be_bytes());
            let decryptor =
                StreamDecryptor::new(Cursor::new(invalid_length), TEST_PASSWORD).unwrap();
            assert!(matches!(
                decryptor.decrypt_to(&mut Vec::new()),
                Err(IronlockError::ResourceLimit(_))
            ));
        }

        let data_len = parse_u32(&encrypted[data_offset + 9..data_offset + 13]).unwrap() as usize;
        for ciphertext_index in [0, data_len - 1] {
            let mut mutated = encrypted.clone();
            mutated[data_offset + RECORD_HEADER_SIZE + ciphertext_index] ^= 1;
            let decryptor = StreamDecryptor::new(Cursor::new(mutated), TEST_PASSWORD).unwrap();
            let mut plaintext = Vec::new();
            assert!(matches!(
                decryptor.decrypt_to(&mut plaintext),
                Err(IronlockError::DecryptionFailed)
            ));
            assert!(plaintext.is_empty());
        }
    }

    #[test]
    fn authenticated_empty_and_oversized_data_records_are_rejected() {
        let metadata = encoded_filename("file.bin");
        let empty_data = build_authenticated_stream(
            1024,
            &metadata,
            &[
                (RECORD_DATA, 1, Vec::new()),
                (RECORD_FINAL, 2, vec![0; FINAL_PLAINTEXT_SIZE]),
            ],
        );
        let decryptor = StreamDecryptor::new(Cursor::new(empty_data), TEST_PASSWORD).unwrap();
        assert!(matches!(
            decryptor.decrypt_to(&mut Vec::new()),
            Err(IronlockError::InvalidFileFormat)
        ));

        let oversized_data = build_authenticated_stream(
            1024,
            &metadata,
            &[
                (RECORD_DATA, 1, vec![0xA5; 1025]),
                (RECORD_FINAL, 2, vec![0; FINAL_PLAINTEXT_SIZE]),
            ],
        );
        let decryptor = StreamDecryptor::new(Cursor::new(oversized_data), TEST_PASSWORD).unwrap();
        assert!(matches!(
            decryptor.decrypt_to(&mut Vec::new()),
            Err(IronlockError::ResourceLimit(_))
        ));
    }

    #[test]
    fn minimum_and_maximum_declared_chunk_sizes_are_accepted() {
        for chunk_size in [1024, MAX_CHUNK_SIZE as u32] {
            let mut final_plaintext = vec![0; FINAL_PLAINTEXT_SIZE];
            final_plaintext[..8].copy_from_slice(&3u64.to_be_bytes());
            final_plaintext[8..].copy_from_slice(&1u64.to_be_bytes());
            let encrypted = build_authenticated_stream(
                chunk_size,
                &encoded_filename("file.bin"),
                &[
                    (RECORD_DATA, 1, b"abc".to_vec()),
                    (RECORD_FINAL, 2, final_plaintext),
                ],
            );
            assert_eq!(decrypt_fixture(&encrypted).unwrap().1, b"abc");
        }
    }

    #[test]
    fn final_record_length_and_counters_are_verified() {
        let metadata = encoded_filename("file.bin");
        for (claimed_len, claimed_chunks) in [(4u64, 1u64), (3, 0), (3, 2)] {
            let mut final_plaintext = vec![0; FINAL_PLAINTEXT_SIZE];
            final_plaintext[..8].copy_from_slice(&claimed_len.to_be_bytes());
            final_plaintext[8..].copy_from_slice(&claimed_chunks.to_be_bytes());
            let encrypted = build_authenticated_stream(
                DEFAULT_CHUNK_SIZE as u32,
                &metadata,
                &[
                    (RECORD_DATA, 1, b"abc".to_vec()),
                    (RECORD_FINAL, 2, final_plaintext),
                ],
            );
            let decryptor = StreamDecryptor::new(Cursor::new(encrypted), TEST_PASSWORD).unwrap();
            assert!(matches!(
                decryptor.decrypt_to(&mut Vec::new()),
                Err(IronlockError::DecryptionFailed)
            ));
        }

        for malformed_final in [Vec::new(), vec![0; FINAL_PLAINTEXT_SIZE - 1]] {
            let encrypted = build_authenticated_stream(
                DEFAULT_CHUNK_SIZE as u32,
                &metadata,
                &[(RECORD_FINAL, 1, malformed_final)],
            );
            let decryptor = StreamDecryptor::new(Cursor::new(encrypted), TEST_PASSWORD).unwrap();
            assert!(matches!(
                decryptor.decrypt_to(&mut Vec::new()),
                Err(IronlockError::InvalidFileFormat)
            ));
        }
    }

    #[test]
    fn missing_final_record_and_critical_truncations_are_rejected() {
        let encrypted = deterministic_fixture("file.bin", &[b"abc", b"def"]);
        let offsets = record_offsets(&encrypted);
        let critical_lengths = [
            HEADER_SIZE,
            offsets[1] - 1,
            offsets[1],
            offsets[1] + RECORD_HEADER_SIZE - 1,
            offsets[2] - 1,
            offsets[2],
            offsets[2] + RECORD_HEADER_SIZE - 1,
            encrypted.len() - 1,
        ];
        for length in critical_lengths {
            let result = StreamDecryptor::new(Cursor::new(&encrypted[..length]), TEST_PASSWORD)
                .and_then(|decryptor| decryptor.decrypt_to(&mut Vec::new()));
            assert!(result.is_err(), "accepted truncation at {length}");
        }
    }

    #[test]
    fn injected_reader_and_writer_failures_are_propagated() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(Error::other("injected failure"))
            }
        }

        let mut encrypted = Vec::new();
        assert!(matches!(
            encrypt_stream_with_params(
                TEST_PASSWORD,
                "file.bin",
                &mut FailingReader,
                &mut encrypted,
                &test_kdf(),
            ),
            Err(IronlockError::IoError(error)) if error.kind() == ErrorKind::Other
        ));

        let mut failing_encrypted_writer = FailingWriter {
            remaining: HEADER_SIZE - 1,
        };
        assert!(matches!(
            encrypt_stream_with_params(
                TEST_PASSWORD,
                "file.bin",
                &mut Cursor::new(b"payload"),
                &mut failing_encrypted_writer,
                &test_kdf(),
            ),
            Err(IronlockError::IoError(error)) if error.kind() == ErrorKind::BrokenPipe
        ));

        assert!(matches!(
            StreamDecryptor::new(FailingReader, TEST_PASSWORD),
            Err(IronlockError::IoError(error)) if error.kind() == ErrorKind::Other
        ));

        let encrypted = deterministic_fixture("file.bin", &[b"payload"]);
        let decryptor = StreamDecryptor::new(Cursor::new(encrypted), TEST_PASSWORD).unwrap();
        let mut failing_plaintext_writer = FailingWriter { remaining: 3 };
        assert!(matches!(
            decryptor.decrypt_to(&mut failing_plaintext_writer),
            Err(IronlockError::IoError(error)) if error.kind() == ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn legacy_wrong_password_is_rejected() {
        let legacy = crate::crypto::create_encrypted_file_with_params(
            TEST_PASSWORD,
            "legacy.txt",
            b"payload",
            &test_kdf(),
        )
        .unwrap();
        assert!(matches!(
            StreamDecryptor::new(Cursor::new(legacy), b"wrong password"),
            Err(IronlockError::DecryptionFailed)
        ));
    }
}
