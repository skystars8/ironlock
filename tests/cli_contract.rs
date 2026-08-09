use std::process::{Command, Output, Stdio};

fn ironlock(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ironlock"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("ironlock binary should start")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn top_level_help_is_a_successful_stable_contract() {
    let output = ironlock(&["--help"]);

    assert!(output.status.success());
    let help = stdout(&output);
    assert!(help.contains("Usage:"));
    assert!(help.contains("encrypt"));
    assert!(help.contains("decrypt"));
    assert!(help.contains("--version"));
    assert!(stderr(&output).is_empty());
}

#[test]
fn version_matches_the_package_version() {
    let output = ironlock(&["--version"]);

    assert!(output.status.success());
    assert_eq!(
        stdout(&output).trim(),
        concat!("ironlock ", env!("CARGO_PKG_VERSION"))
    );
    assert!(stderr(&output).is_empty());
}

#[test]
fn propagated_subcommand_version_matches_the_package_version() {
    for (command, canonical) in [
        ("encrypt", "encrypt"),
        ("decrypt", "decrypt"),
        ("enc", "encrypt"),
        ("dec", "decrypt"),
    ] {
        let output = ironlock(&[command, "--version"]);
        assert!(output.status.success(), "{command}: {}", stderr(&output));
        assert_eq!(
            stdout(&output).trim(),
            format!("ironlock-{canonical} {}", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn subcommand_help_documents_safety_relevant_options() {
    let encrypt = ironlock(&["encrypt", "--help"]);
    assert!(encrypt.status.success());
    let encrypt_help = stdout(&encrypt);
    assert!(encrypt_help.contains("--force"));
    assert!(encrypt_help.contains("--shred"));
    assert!(encrypt_help.contains("not guaranteed media sanitization"));

    let decrypt = ironlock(&["decrypt", "--help"]);
    assert!(decrypt.status.success());
    let decrypt_help = stdout(&decrypt);
    assert!(decrypt_help.contains("--output"));
    assert!(decrypt_help.contains("--force"));
}

#[test]
fn missing_subcommand_returns_clap_usage_error() {
    let output = ironlock(&[]);

    assert_eq!(output.status.code(), Some(2));
    let error = stderr(&output);
    assert!(error.contains("Usage:"));
    assert!(error.contains("<COMMAND>"));
}

#[test]
fn unknown_subcommand_returns_clap_usage_error() {
    let output = ironlock(&["archive"]);

    assert_eq!(output.status.code(), Some(2));
    let error = stderr(&output);
    assert!(error.contains("unrecognized subcommand"));
    assert!(error.contains("Usage:"));
}

#[test]
fn command_specific_flags_are_rejected_on_the_other_command() {
    let encrypt = ironlock(&["encrypt", "--output", "out", "file.txt"]);
    assert_eq!(encrypt.status.code(), Some(2));
    assert!(stderr(&encrypt).contains("unexpected argument '--output'"));

    let decrypt = ironlock(&["decrypt", "--shred", "file.il"]);
    assert_eq!(decrypt.status.code(), Some(2));
    assert!(stderr(&decrypt).contains("unexpected argument '--shred'"));
}

#[test]
fn missing_encrypt_input_fails_before_requesting_a_password() {
    let output = ironlock(&["encrypt", "__ironlock_missing_contract_input__"]);

    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(error.contains("File not found"));
    assert!(!error.contains("Enter password"));
}

#[test]
fn missing_decrypt_input_fails_before_requesting_a_password() {
    let output = ironlock(&["decrypt", "__ironlock_missing_contract_input__.il"]);

    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(error.contains("File not found"));
    assert!(!error.contains("Enter password"));
}
