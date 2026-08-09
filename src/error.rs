use thiserror::Error;

#[derive(Error, Debug)]
pub enum IronlockError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid file extension: expected .il for decryption")]
    InvalidExtension,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: incorrect password or corrupted file")]
    DecryptionFailed,

    #[error("Invalid file format: not a valid Ironlock encrypted file")]
    InvalidFileFormat,

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Passwords do not match")]
    PasswordMismatch,

    #[error("Password cannot be empty")]
    EmptyPassword,

    #[error("No files specified; pipe data to stdin or provide file paths")]
    NoInput,

    #[error("No files eligible for {operation} were found")]
    NoFilesToProcess { operation: &'static str },

    #[error("Secure deletion failed: {0}")]
    SecureDeletionFailed(String),

    #[error("Not a directory: {0}")]
    NotADirectory(String),

    #[error("Unsafe path: {0}")]
    UnsafePath(String),

    #[error("Output collision: {0}")]
    OutputCollision(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("Batch incomplete: {failed} failed, {skipped} skipped")]
    BatchIncomplete { failed: usize, skipped: usize },

    #[error("Operation cancelled by user")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, IronlockError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;
    use std::io;

    #[test]
    fn file_not_found_preserves_path_context() {
        let error = IronlockError::FileNotFound("vault/secret.txt".into());

        assert_eq!(error.to_string(), "File not found: vault/secret.txt");
    }

    #[test]
    fn invalid_extension_has_actionable_message() {
        assert_eq!(
            IronlockError::InvalidExtension.to_string(),
            "Invalid file extension: expected .il for decryption"
        );
    }

    #[test]
    fn encryption_failure_preserves_context() {
        let error = IronlockError::EncryptionFailed("nonce generation failed".into());

        assert_eq!(
            error.to_string(),
            "Encryption failed: nonce generation failed"
        );
    }

    #[test]
    fn decryption_failure_does_not_distinguish_password_from_tampering() {
        assert_eq!(
            IronlockError::DecryptionFailed.to_string(),
            "Decryption failed: incorrect password or corrupted file"
        );
    }

    #[test]
    fn invalid_format_has_stable_message() {
        assert_eq!(
            IronlockError::InvalidFileFormat.to_string(),
            "Invalid file format: not a valid Ironlock encrypted file"
        );
    }

    #[test]
    fn io_error_conversion_preserves_kind_message_and_source() {
        let error: IronlockError = io::Error::new(io::ErrorKind::PermissionDenied, "denied").into();

        assert_eq!(error.to_string(), "I/O error: denied");
        let source = error.source().expect("I/O errors should expose a source");
        assert_eq!(source.to_string(), "denied");
        match error {
            IronlockError::IoError(inner) => {
                assert_eq!(inner.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected I/O error, got {other:?}"),
        }
    }

    #[test]
    fn password_errors_are_distinct() {
        assert_eq!(
            IronlockError::PasswordMismatch.to_string(),
            "Passwords do not match"
        );
        assert_eq!(
            IronlockError::EmptyPassword.to_string(),
            "Password cannot be empty"
        );
    }

    #[test]
    fn no_input_error_explains_both_supported_input_modes() {
        let message = IronlockError::NoInput.to_string();

        assert!(message.contains("pipe data to stdin"));
        assert!(message.contains("provide file paths"));
    }

    #[test]
    fn empty_batch_error_identifies_the_operation() {
        let error = IronlockError::NoFilesToProcess {
            operation: "decryption",
        };

        assert_eq!(
            error.to_string(),
            "No files eligible for decryption were found"
        );
    }

    #[test]
    fn secure_deletion_failure_preserves_context() {
        let error = IronlockError::SecureDeletionFailed("read-only filesystem".into());

        assert_eq!(
            error.to_string(),
            "Secure deletion failed: read-only filesystem"
        );
    }

    #[test]
    fn path_errors_preserve_the_rejected_path() {
        assert_eq!(
            IronlockError::NotADirectory("output.txt".into()).to_string(),
            "Not a directory: output.txt"
        );
        assert_eq!(
            IronlockError::UnsafePath("../escape".into()).to_string(),
            "Unsafe path: ../escape"
        );
        assert_eq!(
            IronlockError::OutputCollision("same.il".into()).to_string(),
            "Output collision: same.il"
        );
    }

    #[test]
    fn resource_limit_error_preserves_limit_context() {
        let error = IronlockError::ResourceLimit("record count exceeds maximum".into());

        assert_eq!(
            error.to_string(),
            "Resource limit exceeded: record count exceeds maximum"
        );
    }

    #[test]
    fn batch_error_reports_failed_and_skipped_counts() {
        let error = IronlockError::BatchIncomplete {
            failed: 3,
            skipped: 2,
        };

        assert_eq!(error.to_string(), "Batch incomplete: 3 failed, 2 skipped");
    }

    #[test]
    fn cancelled_error_has_stable_message() {
        assert_eq!(
            IronlockError::Cancelled.to_string(),
            "Operation cancelled by user"
        );
    }

    #[test]
    fn result_alias_supports_success_and_typed_errors() {
        let success: Result<u8> = Ok(7);
        assert!(matches!(success, Ok(7)));

        let failure: Result<u8> = Err(IronlockError::EmptyPassword);
        assert!(matches!(failure, Err(IronlockError::EmptyPassword)));
    }
}
