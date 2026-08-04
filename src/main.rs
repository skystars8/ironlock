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
use zeroize::Zeroizing;

use cli::{Cli, Commands};
use error::{IronlockError, Result};
use file_ops::{
    decrypt_file_to_path, encrypt_file_to_path, plan_decryption_inputs, plan_encryption_inputs,
};
use memlock::mlock_slice;
use stream_crypto::{encrypt_stream, StreamDecryptor};

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    let password = rpassword::read_password()
        .map_err(|error| IronlockError::IoError(io::Error::other(error)))?;
    mlock_slice(password.as_bytes());
    Ok(Zeroizing::new(password))
}

fn prompt_password_with_confirm() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;
    if password.is_empty() {
        return Err(IronlockError::EmptyPassword);
    }

    let confirm = prompt_password("Confirm password: ")?;
    if *password != *confirm {
        return Err(IronlockError::PasswordMismatch);
    }
    Ok(password)
}

fn prompt_password_decrypt() -> Result<Zeroizing<String>> {
    let password = prompt_password("Enter password: ")?;
    if password.is_empty() {
        return Err(IronlockError::EmptyPassword);
    }
    Ok(password)
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

fn require_piped_stdin() {
    if io::stdin().is_terminal() {
        eprintln!(
            "{} No files specified. Pipe data to stdin or provide file paths.",
            "Error:".red().bold()
        );
        std::process::exit(1);
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
        let suffix = match &result {
            Ok(output_path) if shredded => format!(
                "{} ? {} (original overwritten/deleted; media-dependent)",
                "?".green(),
                output_path.display()
            ),
            Ok(output_path) => format!("{} ? {}", "?".green(), output_path.display()),
            Err(IronlockError::Cancelled) => "skipped".yellow().to_string(),
            Err(IronlockError::DecryptionFailed) => {
                format!("{} incorrect password or corrupted file", "?".red())
            }
            Err(error) => format!("{} {error}", "?".red()),
        };
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
                "?".green(),
                self.success,
                operation
            );
            Ok(())
        } else {
            println!(
                "{} {} succeeded, {} failed, {} skipped",
                "?".yellow(),
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
                require_piped_stdin();
                let password = prompt_password_with_confirm()?;
                eprintln!();
                encrypt_stdin(password.as_bytes())?;
            } else {
                // Resolve every input and output before the first modification.
                let plans = plan_encryption_inputs(&files)?;

                println!("{}", "?? Ironlock Encryption".cyan().bold());
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
                require_piped_stdin();
                let password = prompt_password_decrypt()?;
                eprintln!();
                decrypt_stdin(password.as_bytes())?;
            } else {
                // Traversal and output-directory structure are validated up front.
                let plans = plan_decryption_inputs(&files, output.as_deref())?;

                println!("{}", "?? Ironlock Decryption".cyan().bold());
                println!();
                let password = prompt_password_decrypt()?;
                println!();

                let progress = progress.then(|| make_progress_bar(plans.len() as u64));
                let mut counters = Counters::new(progress);
                for plan in plans {
                    let prefix = format!("Decrypting {} ... ", plan.source.display());
                    let result = decrypt_file_to_path(
                        &plan.source,
                        password.as_bytes(),
                        Some(&plan.target_dir),
                        force,
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
        eprintln!("{} {error}", "Error".red().bold());
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
