use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Ironlock - A secure file encryption tool
///
/// Encrypts files using Argon2id for key derivation and ChaCha20-Poly1305 for
/// authenticated encryption.
#[derive(Parser, Debug)]
#[command(name = "ironlock")]
#[command(author, version, about, long_about = None)]
#[command(arg_required_else_help = true)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt one or more files
    ///
    /// Files will be encrypted and saved with the .il extension.
    /// Original files are preserved unless --shred is used.
    /// If no files are specified, reads from stdin and writes to stdout.
    #[command(visible_alias = "enc", visible_alias = "e")]
    Encrypt {
        /// Files to encrypt (reads from stdin if omitted)
        #[arg(num_args = 0..)]
        files: Vec<PathBuf>,

        /// Force overwrite without prompting if output file exists
        #[arg(short, long, default_value_t = false, requires = "files")]
        force: bool,

        /// Best-effort overwrite/delete originals after encryption.
        /// This is not guaranteed media sanitization on SSDs, snapshots, or CoW storage.
        #[arg(
            short = 's',
            long,
            visible_alias = "delete",
            default_value_t = false,
            requires = "files"
        )]
        shred: bool,

        /// Show a progress bar while processing files
        #[arg(short, long, default_value_t = false, requires = "files")]
        progress: bool,
    },

    /// Decrypt one or more .il files
    ///
    /// Files will be decrypted and restored to their original format.
    /// If no files are specified, reads from stdin and writes to stdout.
    #[command(visible_alias = "dec", visible_alias = "d")]
    Decrypt {
        /// Files to decrypt (reads from stdin if omitted)
        #[arg(num_args = 0..)]
        files: Vec<PathBuf>,

        /// Output directory (file inputs default to current directory; directories restore in place)
        #[arg(short, long, requires = "files")]
        output: Option<PathBuf>,

        /// Force overwrite without prompting if output file exists
        #[arg(short, long, default_value_t = false, requires = "files")]
        force: bool,

        /// Show a progress bar while processing files
        #[arg(short, long, default_value_t = false, requires = "files")]
        progress: bool,
    },
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;
    use clap::CommandFactory;

    // ==================== Basic Parsing Tests ====================

    #[test]
    fn test_cli_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_encrypt_single_file() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt {
                files,
                force,
                shred,
                progress,
            } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0], PathBuf::from("file.txt"));
                assert!(!force);
                assert!(!shred);
                assert!(!progress);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_multiple_files() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "a.txt", "b.pdf", "c.doc"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files.len(), 3);
                assert_eq!(files[0], PathBuf::from("a.txt"));
                assert_eq!(files[1], PathBuf::from("b.pdf"));
                assert_eq!(files[2], PathBuf::from("c.doc"));
                assert!(!force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_force_short() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-f", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files.len(), 1);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_force_long() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--force", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { force, shred, .. } => {
                assert!(force);
                assert!(!shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_single_file() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt", "file.il"]).unwrap();

        match cli.command {
            Commands::Decrypt {
                files,
                output,
                force,
                progress,
            } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0], PathBuf::from("file.il"));
                assert!(output.is_none());
                assert!(!force);
                assert!(!progress);
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_output_short() {
        let cli =
            Cli::try_parse_from(["ironlock", "decrypt", "file.il", "-o", "./output/"]).unwrap();

        match cli.command {
            Commands::Decrypt { output, .. } => {
                assert_eq!(output, Some(PathBuf::from("./output/")));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_output_long() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt", "file.il", "--output", "/tmp/out"])
            .unwrap();

        match cli.command {
            Commands::Decrypt { output, .. } => {
                assert_eq!(output, Some(PathBuf::from("/tmp/out")));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_force_and_output() {
        let cli = Cli::try_parse_from([
            "ironlock", "decrypt", "a.il", "b.il", "-o", "./out", "--force",
        ])
        .unwrap();

        match cli.command {
            Commands::Decrypt {
                files,
                output,
                force,
                ..
            } => {
                assert_eq!(files.len(), 2);
                assert_eq!(output, Some(PathBuf::from("./out")));
                assert!(force);
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    // ==================== Alias Tests ====================

    #[test]
    fn test_encrypt_alias_enc() {
        let cli = Cli::try_parse_from(["ironlock", "enc", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_alias_e() {
        let cli = Cli::try_parse_from(["ironlock", "e", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_alias_dec() {
        let cli = Cli::try_parse_from(["ironlock", "dec", "file.il"]).unwrap();

        match cli.command {
            Commands::Decrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.il"));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_decrypt_alias_d() {
        let cli = Cli::try_parse_from(["ironlock", "d", "file.il"]).unwrap();

        match cli.command {
            Commands::Decrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("file.il"));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    // ==================== Error Cases ====================

    #[test]
    fn test_encrypt_no_files_is_valid() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt"]).unwrap();
        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert!(files.is_empty());
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_no_files_is_valid() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt"]).unwrap();
        match cli.command {
            Commands::Decrypt { files, .. } => {
                assert!(files.is_empty());
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_unknown_command_fails() {
        let result = Cli::try_parse_from(["ironlock", "unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_command_fails() {
        let result = Cli::try_parse_from(["ironlock"]);
        assert!(result.is_err());
    }

    // ==================== Path Handling Tests ====================

    #[test]
    fn test_absolute_path() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "/home/user/secret.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("/home/user/secret.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_relative_path_with_dots() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "../parent/file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("../parent/file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_path_with_spaces() {
        let cli =
            Cli::try_parse_from(["ironlock", "encrypt", "path with spaces/file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files[0], PathBuf::from("path with spaces/file.txt"));
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    // ==================== Shred Flag Tests ====================

    #[test]
    fn test_encrypt_with_shred_short() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-s", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { shred, .. } => {
                assert!(shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_shred_long() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--shred", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { shred, .. } => {
                assert!(shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_delete_alias() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--delete", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { shred, .. } => {
                assert!(shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_shred_defaults_to_false() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { shred, .. } => {
                assert!(!shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_shred_and_force() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-f", "-s", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { force, shred, .. } => {
                assert!(force);
                assert!(shred);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    // ==================== Progress Flag Tests ====================

    #[test]
    fn test_encrypt_with_progress_short() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-p", "file.txt"]).unwrap();
        match cli.command {
            Commands::Encrypt { progress, .. } => assert!(progress),
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_encrypt_with_progress_long() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--progress", "file.txt"]).unwrap();
        match cli.command {
            Commands::Encrypt { progress, .. } => assert!(progress),
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn test_decrypt_with_progress() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt", "--progress", "file.il"]).unwrap();
        match cli.command {
            Commands::Decrypt { progress, .. } => assert!(progress),
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn test_progress_defaults_to_false() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "file.txt"]).unwrap();
        match cli.command {
            Commands::Encrypt { progress, .. } => assert!(!progress),
            _ => panic!("Expected Encrypt command"),
        }
    }

    // ==================== Mixed Flag Tests ====================

    #[test]
    fn test_mixed_flags_and_files() {
        // Force flag before files
        let cli1 = Cli::try_parse_from(["ironlock", "encrypt", "-f", "a.txt", "b.txt"]).unwrap();
        match cli1.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files.len(), 2);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }

        // Force flag after files
        let cli2 = Cli::try_parse_from(["ironlock", "encrypt", "a.txt", "b.txt", "-f"]).unwrap();
        match cli2.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files.len(), 2);
                assert!(force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    // ==================== CLI Contract Tests ====================

    #[test]
    fn missing_command_displays_help() {
        let error = Cli::try_parse_from(["ironlock"]).unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
        let rendered = error.to_string();
        assert!(rendered.contains("Usage:"));
        assert!(rendered.contains("<COMMAND>"));
    }

    #[test]
    fn unknown_command_is_an_invalid_subcommand() {
        let error = Cli::try_parse_from(["ironlock", "archive"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
        assert!(error.to_string().contains("unrecognized subcommand"));
    }

    #[test]
    fn top_level_help_lists_commands_and_aliases() {
        let error = Cli::try_parse_from(["ironlock", "--help"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("encrypt"));
        assert!(help.contains("enc, e"));
        assert!(help.contains("decrypt"));
        assert!(help.contains("dec, d"));
    }

    #[test]
    fn version_comes_from_package_metadata() {
        let error = Cli::try_parse_from(["ironlock", "--version"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        assert_eq!(
            error.to_string().trim(),
            concat!("ironlock ", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn propagated_subcommand_version_uses_canonical_name() {
        for (command, canonical) in [
            ("encrypt", "encrypt"),
            ("enc", "encrypt"),
            ("e", "encrypt"),
            ("decrypt", "decrypt"),
            ("dec", "decrypt"),
            ("d", "decrypt"),
        ] {
            let error = Cli::try_parse_from(["ironlock", command, "--version"]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::DisplayVersion, "{command}");
            assert_eq!(
                error.to_string().trim(),
                format!("ironlock-{canonical} {}", env!("CARGO_PKG_VERSION")),
                "{command}"
            );
        }
    }

    #[test]
    fn encrypt_help_is_precise_and_documents_safety() {
        let error = Cli::try_parse_from(["ironlock", "encrypt", "--help"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("Files will be encrypted"));
        assert!(!help.contains("Fields will be encrypted"));
        assert!(!help.contains("military-grade"));
        assert!(help.contains("not guaranteed media sanitization"));
        assert!(help.contains("--delete"));
    }

    #[test]
    fn decrypt_help_documents_output_and_stream_modes() {
        let error = Cli::try_parse_from(["ironlock", "decrypt", "--help"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("--output"));
        assert!(help.contains("reads from stdin"));
        assert!(help.contains("writes to stdout"));
    }

    #[test]
    fn encrypt_rejects_file_only_flags_without_files() {
        for flag in ["--force", "--shred", "--delete", "--progress"] {
            let error = Cli::try_parse_from(["ironlock", "encrypt", flag]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument, "{flag}");
            assert!(error.to_string().contains("[FILES]..."), "{flag}");
        }
    }

    #[test]
    fn decrypt_rejects_file_only_boolean_flags_without_files() {
        for flag in ["--force", "--progress"] {
            let error = Cli::try_parse_from(["ironlock", "decrypt", flag]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument, "{flag}");
            assert!(error.to_string().contains("[FILES]..."), "{flag}");
        }
    }

    #[test]
    fn decrypt_rejects_output_without_files() {
        let error = Cli::try_parse_from(["ironlock", "decrypt", "--output", "out"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        assert!(error.to_string().contains("[FILES]..."));
    }

    #[test]
    fn empty_encrypt_path_is_rejected() {
        let error = Cli::try_parse_from(["ironlock", "encrypt", ""]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
        assert!(error.to_string().contains("value is required"));
    }

    #[test]
    fn empty_decrypt_path_is_rejected() {
        let error = Cli::try_parse_from(["ironlock", "decrypt", ""]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
        assert!(error.to_string().contains("value is required"));
    }

    #[test]
    fn empty_output_path_is_rejected() {
        let error =
            Cli::try_parse_from(["ironlock", "decrypt", "file.il", "--output", ""]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
        assert!(error.to_string().contains("value is required"));
    }

    #[test]
    fn option_terminator_allows_hyphen_prefixed_encrypt_path() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "--", "--force"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, force, .. } => {
                assert_eq!(files, [PathBuf::from("--force")]);
                assert!(!force);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn option_terminator_allows_hyphen_prefixed_decrypt_path() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt", "--", "--output"]).unwrap();

        match cli.command {
            Commands::Decrypt { files, output, .. } => {
                assert_eq!(files, [PathBuf::from("--output")]);
                assert!(output.is_none());
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn combined_encrypt_short_flags_are_supported() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "-fsp", "file.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt {
                files,
                force,
                shred,
                progress,
            } => {
                assert_eq!(files, [PathBuf::from("file.txt")]);
                assert!(force);
                assert!(shred);
                assert!(progress);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn combined_decrypt_short_flags_are_supported() {
        let cli =
            Cli::try_parse_from(["ironlock", "decrypt", "-fp", "-o", "out", "file.il"]).unwrap();

        match cli.command {
            Commands::Decrypt {
                files,
                output,
                force,
                progress,
            } => {
                assert_eq!(files, [PathBuf::from("file.il")]);
                assert_eq!(output, Some(PathBuf::from("out")));
                assert!(force);
                assert!(progress);
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn output_accepts_equals_syntax() {
        let cli = Cli::try_parse_from(["ironlock", "decrypt", "--output=out", "file.il"]).unwrap();

        match cli.command {
            Commands::Decrypt { output, .. } => {
                assert_eq!(output, Some(PathBuf::from("out")));
            }
            _ => panic!("Expected Decrypt command"),
        }
    }

    #[test]
    fn unicode_paths_are_preserved() {
        let cli = Cli::try_parse_from(["ironlock", "encrypt", "秘密/🔒.txt"]).unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files, [PathBuf::from("秘密/🔒.txt")]);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn non_unicode_windows_paths_are_preserved() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let path = OsString::from_wide(&[b'f' as u16, 0xD800, b'x' as u16]);
        let cli = Cli::try_parse_from([
            OsString::from("ironlock"),
            OsString::from("encrypt"),
            path.clone(),
        ])
        .unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files, [PathBuf::from(path)]);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_unix_paths_are_preserved() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = OsString::from_vec(vec![b'f', 0xFF, b'x']);
        let cli = Cli::try_parse_from([
            OsString::from("ironlock"),
            OsString::from("encrypt"),
            path.clone(),
        ])
        .unwrap();

        match cli.command {
            Commands::Encrypt { files, .. } => {
                assert_eq!(files, [PathBuf::from(path)]);
            }
            _ => panic!("Expected Encrypt command"),
        }
    }

    #[test]
    fn command_specific_options_are_rejected_elsewhere() {
        let encrypt_error =
            Cli::try_parse_from(["ironlock", "encrypt", "--output", "out", "file.txt"])
                .unwrap_err();
        assert_eq!(encrypt_error.kind(), ErrorKind::UnknownArgument);

        let decrypt_error =
            Cli::try_parse_from(["ironlock", "decrypt", "--shred", "file.il"]).unwrap_err();
        assert_eq!(decrypt_error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn missing_output_value_is_rejected() {
        let error =
            Cli::try_parse_from(["ironlock", "decrypt", "file.il", "--output"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn command_names_are_case_sensitive() {
        let error = Cli::try_parse_from(["ironlock", "Encrypt", "file.txt"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
    }
}
