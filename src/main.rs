#![deny(clippy::undocumented_unsafe_blocks)]

mod cli;
mod crypto;
mod error;
mod file_ops;
mod memlock;
mod secure_fs;
mod stream_crypto;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

use cli::{Cli, Commands};
use error::{IronlockError, Result};
use file_ops::{
    decrypt_file_to_path_guarded, encrypt_file_to_path, plan_decryption_inputs,
    plan_encryption_inputs, DecryptionBatchGuard,
};
use memlock::LockedString;
use stream_crypto::{encrypt_stream, StreamDecryptor};

fn prompt_password(prompt: &str) -> Result<LockedString> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    let password = rpassword::read_password()
        .map_err(|error| IronlockError::IoError(io::Error::other(error)))?;
    Ok(LockedString::new(password))
}

fn prompt_password_with_confirm() -> Result<LockedString> {
    let password = prompt_password("Enter password: ")?;
    validate_password(&password)?;

    let confirm = prompt_password("Confirm password: ")?;
    validate_password_confirmation(&password, &confirm)?;
    Ok(password)
}

fn prompt_password_decrypt() -> Result<LockedString> {
    let password = prompt_password("Enter password: ")?;
    validate_password(&password)?;
    Ok(password)
}

fn validate_password(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(IronlockError::EmptyPassword);
    }
    Ok(())
}

fn validate_password_confirmation(password: &str, confirmation: &str) -> Result<()> {
    if password != confirmation {
        return Err(IronlockError::PasswordMismatch);
    }
    Ok(())
}

fn encrypt_stdin(password: &[u8]) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    encrypt_stream(password, "stdin", &mut reader, &mut writer)?;
    writer.flush()?;
    Ok(())
}

fn decrypt_stdin(password: &[u8]) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let reader = stdin.lock();
    let mut writer = stdout.lock();
    let decryptor = StreamDecryptor::new(reader, password)?;
    decryptor.decrypt_to(&mut writer)?;
    writer.flush()?;
    Ok(())
}

fn require_piped_stdin() -> Result<()> {
    validate_stream_input(io::stdin().is_terminal())
}

fn validate_stream_input(stdin_is_terminal: bool) -> Result<()> {
    if stdin_is_terminal {
        Err(IronlockError::NoInput)
    } else {
        Ok(())
    }
}

fn require_non_empty_batch<T>(items: &[T], operation: &'static str) -> Result<()> {
    if items.is_empty() {
        Err(IronlockError::NoFilesToProcess { operation })
    } else {
        Ok(())
    }
}

fn make_progress_bar(total: u64) -> ProgressBar {
    let progress = ProgressBar::new(total);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .expect("progress template is valid")
            .progress_chars("=> "),
    );
    progress
}

struct Counters {
    success: usize,
    errors: usize,
    skipped: usize,
    progress: Option<ProgressBar>,
}

impl Counters {
    fn new(progress: Option<ProgressBar>) -> Self {
        Self {
            success: 0,
            errors: 0,
            skipped: 0,
            progress,
        }
    }

    fn output(&self, message: &str) {
        match &self.progress {
            Some(progress) => progress.println(message),
            None => println!("{message}"),
        }
    }

    fn handle_result(
        &mut self,
        prefix: &str,
        result: std::result::Result<PathBuf, IronlockError>,
        shredded: bool,
    ) {
        let suffix = format_result_suffix(&result, shredded);
        self.output(&format!("{prefix}{suffix}"));

        match result {
            Ok(_) => self.success += 1,
            Err(IronlockError::Cancelled) => self.skipped += 1,
            Err(_) => self.errors += 1,
        }
        if let Some(progress) = &self.progress {
            progress.inc(1);
        }
    }

    fn print_summary(&self, operation: &str) -> Result<()> {
        if let Some(progress) = &self.progress {
            progress.finish_and_clear();
        }
        println!();

        if self.errors == 0 && self.skipped == 0 {
            println!(
                "{} {} file(s) {} successfully",
                "[OK]".green(),
                self.success,
                operation
            );
            Ok(())
        } else {
            println!(
                "{} {} succeeded, {} failed, {} skipped",
                "[WARN]".yellow(),
                self.success,
                self.errors,
                self.skipped
            );
            Err(IronlockError::BatchIncomplete {
                failed: self.errors,
                skipped: self.skipped,
            })
        }
    }
}

fn format_result_suffix(
    result: &std::result::Result<PathBuf, IronlockError>,
    shredded: bool,
) -> String {
    match result {
        Ok(output_path) if shredded => format!(
            "{} -> {} (original overwritten/deleted; media-dependent)",
            "[OK]".green(),
            output_path.display()
        ),
        Ok(output_path) => format!("{} -> {}", "[OK]".green(), output_path.display()),
        Err(IronlockError::Cancelled) => "[SKIPPED]".yellow().to_string(),
        Err(IronlockError::DecryptionFailed) => {
            format!("{} incorrect password or corrupted file", "[ERROR]".red())
        }
        Err(error) => format!("{} {error}", "[ERROR]".red()),
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse_args();

    match cli.command {
        Commands::Encrypt {
            files,
            force,
            shred,
            progress,
        } => {
            if files.is_empty() {
                require_piped_stdin()?;
                let password = prompt_password_with_confirm()?;
                eprintln!();
                encrypt_stdin(password.as_bytes())?;
            } else {
                // Resolve every input and output before the first modification.
                let plans = plan_encryption_inputs(&files)?;
                require_non_empty_batch(&plans, "encryption")?;

                println!("{}", "Ironlock Encryption".cyan().bold());
                println!();
                let password = prompt_password_with_confirm()?;
                println!();

                let progress = progress.then(|| make_progress_bar(plans.len() as u64));
                let mut counters = Counters::new(progress);
                for plan in plans {
                    let prefix = format!("Encrypting {} ... ", plan.source.display());
                    let result = encrypt_file_to_path(
                        &plan.source,
                        &plan.output,
                        password.as_bytes(),
                        force,
                        shred,
                    );
                    counters.handle_result(&prefix, result, shred);
                }
                counters.print_summary("encrypted")?;
            }
        }
        Commands::Decrypt {
            files,
            output,
            force,
            progress,
        } => {
            if files.is_empty() {
                require_piped_stdin()?;
                let password = prompt_password_decrypt()?;
                eprintln!();
                decrypt_stdin(password.as_bytes())?;
            } else {
                // Traversal and output-directory structure are validated up front.
                let plans = plan_decryption_inputs(&files, output.as_deref())?;
                require_non_empty_batch(&plans, "decryption")?;
                let mut batch_guard = DecryptionBatchGuard::new(&plans)?;

                println!("{}", "Ironlock Decryption".cyan().bold());
                println!();
                let password = prompt_password_decrypt()?;
                println!();

                let progress = progress.then(|| make_progress_bar(plans.len() as u64));
                let mut counters = Counters::new(progress);
                for plan in plans {
                    let prefix = format!("Decrypting {} ... ", plan.source.display());
                    let result = decrypt_file_to_path_guarded(
                        &plan.source,
                        password.as_bytes(),
                        Some(&plan.target_dir),
                        force,
                        &mut batch_guard,
                    );
                    counters.handle_result(&prefix, result, false);
                }
                counters.print_summary("decrypted")?;
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{} {error}", "Error:".red().bold());
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_empty_password_is_valid() {
        assert!(validate_password("correct horse battery staple").is_ok());
    }

    #[test]
    fn unicode_password_is_valid() {
        assert!(validate_password("秘密🔒").is_ok());
    }

    #[test]
    fn whitespace_password_is_not_silently_changed() {
        assert!(validate_password("   ").is_ok());
    }

    #[test]
    fn locked_password_integrates_without_mutating_text() {
        let password = LockedString::new("pässword 🔐".to_string());

        assert!(validate_password(&password).is_ok());
        assert!(validate_password_confirmation(&password, "pässword 🔐").is_ok());
        assert_eq!(password.as_bytes(), "pässword 🔐".as_bytes());
    }

    #[test]
    fn empty_password_returns_typed_error() {
        assert!(matches!(
            validate_password(""),
            Err(IronlockError::EmptyPassword)
        ));
    }

    #[test]
    fn matching_password_confirmation_is_valid() {
        assert!(validate_password_confirmation("sëcret", "sëcret").is_ok());
    }

    #[test]
    fn password_confirmation_is_exact_and_case_sensitive() {
        assert!(matches!(
            validate_password_confirmation("Secret", "secret"),
            Err(IronlockError::PasswordMismatch)
        ));
    }

    #[test]
    fn password_confirmation_preserves_whitespace() {
        assert!(matches!(
            validate_password_confirmation("secret ", "secret"),
            Err(IronlockError::PasswordMismatch)
        ));
    }

    #[test]
    fn piped_stream_input_is_accepted() {
        assert!(validate_stream_input(false).is_ok());
    }

    #[test]
    fn terminal_without_files_returns_typed_error() {
        assert!(matches!(
            validate_stream_input(true),
            Err(IronlockError::NoInput)
        ));
    }

    #[test]
    fn non_empty_batch_is_accepted() {
        assert!(require_non_empty_batch(&["file"], "encryption").is_ok());
    }

    #[test]
    fn empty_encryption_batch_returns_typed_error() {
        assert!(matches!(
            require_non_empty_batch::<()>(&[], "encryption"),
            Err(IronlockError::NoFilesToProcess {
                operation: "encryption"
            })
        ));
    }

    #[test]
    fn empty_decryption_batch_returns_typed_error() {
        assert!(matches!(
            require_non_empty_batch::<()>(&[], "decryption"),
            Err(IronlockError::NoFilesToProcess {
                operation: "decryption"
            })
        ));
    }

    #[test]
    fn progress_bar_starts_at_zero_with_requested_length() {
        let progress = make_progress_bar(7);

        assert_eq!(progress.length(), Some(7));
        assert_eq!(progress.position(), 0);
        assert!(!progress.is_finished());
        progress.finish_and_clear();
    }

    #[test]
    fn new_counters_start_empty() {
        let counters = Counters::new(None);

        assert_eq!(counters.success, 0);
        assert_eq!(counters.errors, 0);
        assert_eq!(counters.skipped, 0);
        assert!(counters.progress.is_none());
    }

    #[test]
    fn successful_result_message_includes_destination() {
        let message = format_result_suffix(&Ok(PathBuf::from("vault.il")), false);

        assert!(message.contains("[OK]"));
        assert!(message.contains("-> vault.il"));
        assert!(!message.contains("overwritten/deleted"));
    }

    #[test]
    fn shredded_result_message_qualifies_secure_deletion() {
        let message = format_result_suffix(&Ok(PathBuf::from("vault.il")), true);

        assert!(message.contains("[OK]"));
        assert!(message.contains("overwritten/deleted"));
        assert!(message.contains("media-dependent"));
    }

    #[test]
    fn cancelled_result_message_is_distinct_from_failure() {
        let message = format_result_suffix(&Err(IronlockError::Cancelled), false);

        assert!(message.contains("[SKIPPED]"));
        assert!(!message.contains("[ERROR]"));
    }

    #[test]
    fn decryption_failure_message_does_not_claim_a_specific_cause() {
        let message = format_result_suffix(&Err(IronlockError::DecryptionFailed), false);

        assert!(message.contains("[ERROR]"));
        assert!(message.contains("incorrect password or corrupted file"));
    }

    #[test]
    fn generic_failure_message_preserves_error_context() {
        let message = format_result_suffix(
            &Err(IronlockError::FileNotFound("missing.txt".into())),
            false,
        );

        assert!(message.contains("[ERROR]"));
        assert!(message.contains("File not found: missing.txt"));
    }

    #[test]
    fn successful_result_increments_only_success_count() {
        let mut counters = Counters::new(None);

        counters.handle_result("", Ok(PathBuf::from("file.il")), false);

        assert_eq!(counters.success, 1);
        assert_eq!(counters.errors, 0);
        assert_eq!(counters.skipped, 0);
    }

    #[test]
    fn cancelled_result_increments_only_skipped_count() {
        let mut counters = Counters::new(None);

        counters.handle_result("", Err(IronlockError::Cancelled), false);

        assert_eq!(counters.success, 0);
        assert_eq!(counters.errors, 0);
        assert_eq!(counters.skipped, 1);
    }

    #[test]
    fn failed_result_increments_only_error_count() {
        let mut counters = Counters::new(None);

        counters.handle_result("", Err(IronlockError::DecryptionFailed), false);

        assert_eq!(counters.success, 0);
        assert_eq!(counters.errors, 1);
        assert_eq!(counters.skipped, 0);
    }

    #[test]
    fn every_result_advances_progress_once() {
        let progress = ProgressBar::hidden();
        progress.set_length(3);
        let mut counters = Counters::new(Some(progress.clone()));

        counters.handle_result("", Ok(PathBuf::from("one.il")), false);
        counters.handle_result("", Err(IronlockError::Cancelled), false);
        counters.handle_result("", Err(IronlockError::DecryptionFailed), false);

        assert_eq!(progress.position(), 3);
        assert_eq!(counters.success, 1);
        assert_eq!(counters.errors, 1);
        assert_eq!(counters.skipped, 1);
    }

    #[test]
    fn complete_batch_returns_success() {
        let counters = Counters {
            success: 2,
            errors: 0,
            skipped: 0,
            progress: None,
        };

        assert!(counters.print_summary("processed").is_ok());
    }

    #[test]
    fn skipped_batch_returns_exact_error_counts() {
        let counters = Counters {
            success: 2,
            errors: 0,
            skipped: 3,
            progress: None,
        };

        assert!(matches!(
            counters.print_summary("processed"),
            Err(IronlockError::BatchIncomplete {
                failed: 0,
                skipped: 3
            })
        ));
    }

    #[test]
    fn failed_batch_returns_exact_error_counts() {
        let counters = Counters {
            success: 0,
            errors: 4,
            skipped: 0,
            progress: None,
        };

        assert!(matches!(
            counters.print_summary("processed"),
            Err(IronlockError::BatchIncomplete {
                failed: 4,
                skipped: 0
            })
        ));
    }

    #[test]
    fn summary_finishes_progress_bar() {
        let progress = ProgressBar::hidden();
        progress.set_length(1);
        let counters = Counters {
            success: 1,
            errors: 0,
            skipped: 0,
            progress: Some(progress.clone()),
        };

        assert!(counters.print_summary("processed").is_ok());
        assert!(progress.is_finished());
    }

    #[test]
    fn incomplete_batch_returns_an_error_exit_condition() {
        let counters = Counters {
            success: 1,
            errors: 1,
            skipped: 0,
            progress: None,
        };
        assert!(matches!(
            counters.print_summary("processed"),
            Err(IronlockError::BatchIncomplete {
                failed: 1,
                skipped: 0
            })
        ));
    }
}
