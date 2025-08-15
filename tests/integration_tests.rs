use assert_cmd::Command;
use predicates::prelude::*;

/// Test the complete generate -> sign -> verify workflow
#[test]
fn test_complete_workflow() {
    // Step 1: Generate a new wallet
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    let generate_output = cmd.arg("generate").assert().success();

    let generate_stdout = String::from_utf8(generate_output.get_output().stdout.clone()).unwrap();

    // Extract private key and public key from the output
    let private_key = extract_private_key(&generate_stdout);
    let public_key = extract_public_key(&generate_stdout);

    assert!(!private_key.is_empty(), "Private key should be extracted");
    assert!(!public_key.is_empty(), "Public key should be extracted");
    assert_eq!(
        private_key.len(),
        64,
        "Private key should be 64 hex characters"
    );
    assert_eq!(
        public_key.len(),
        66,
        "Public key should be 66 hex characters"
    );

    // Step 2: Sign a message with the generated private key
    let test_message = "Hello, blockchain world!";
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    let sign_output = cmd
        .arg("sign")
        .arg("--message")
        .arg(test_message)
        .arg("--private-key")
        .arg(&private_key)
        .assert()
        .success();

    let sign_stdout = String::from_utf8(sign_output.get_output().stdout.clone()).unwrap();
    let signature = extract_signature(&sign_stdout);

    assert!(!signature.is_empty(), "Signature should be extracted");
    assert_eq!(
        signature.len(),
        128,
        "Signature should be 128 hex characters"
    );

    // Step 3: Verify the signature with the public key
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("verify")
        .arg("--message")
        .arg(test_message)
        .arg("--signature")
        .arg(&signature)
        .arg("--public-key")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Signature verification SUCCESSFUL",
        ));
}

/// Test generate command produces valid output
#[test]
fn test_generate_command() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("generate")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "New wallet generated successfully",
        ))
        .stdout(predicate::str::contains("Private Key:"))
        .stdout(predicate::str::contains("Public Key:"))
        .stdout(predicate::str::contains("Address:"))
        .stdout(predicate::str::contains(
            "IMPORTANT: Keep your private key secure",
        ));
}

/// Test generate command produces different keys each time
#[test]
fn test_generate_command_randomness() {
    // Generate first wallet
    let mut cmd1 = Command::cargo_bin("cli-wallet").unwrap();
    let output1 = cmd1.arg("generate").assert().success();
    let stdout1 = String::from_utf8(output1.get_output().stdout.clone()).unwrap();
    let private_key1 = extract_private_key(&stdout1);

    // Generate second wallet
    let mut cmd2 = Command::cargo_bin("cli-wallet").unwrap();
    let output2 = cmd2.arg("generate").assert().success();
    let stdout2 = String::from_utf8(output2.get_output().stdout.clone()).unwrap();
    let private_key2 = extract_private_key(&stdout2);

    // Keys should be different (extremely unlikely to be the same)
    assert_ne!(
        private_key1, private_key2,
        "Generated keys should be different"
    );
}

/// Test sign command with valid inputs
#[test]
fn test_sign_command_valid() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("sign")
        .arg("--message")
        .arg("test message")
        .arg("--private-key")
        .arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .assert()
        .success()
        .stdout(predicate::str::contains("Message signed successfully"))
        .stdout(predicate::str::contains("Message:"))
        .stdout(predicate::str::contains("Signature:"))
        .stdout(predicate::str::contains("You can verify this signature"));
}

/// Test sign command with invalid private key
#[test]
fn test_sign_command_invalid_private_key() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("sign")
        .arg("--message")
        .arg("test message")
        .arg("--private-key")
        .arg("invalid_key")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Private key must be 64 hex characters",
        ));
}

/// Test sign command with empty message
#[test]
fn test_sign_command_empty_message() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("sign")
        .arg("--message")
        .arg("")
        .arg("--private-key")
        .arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Message cannot be empty"));
}

/// Test verify command with valid signature
#[test]
fn test_verify_command_valid() {
    // First create a valid signature
    let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let message = "test message";

    let mut sign_cmd = Command::cargo_bin("cli-wallet").unwrap();
    let sign_output = sign_cmd
        .arg("sign")
        .arg("--message")
        .arg(message)
        .arg("--private-key")
        .arg(private_key)
        .assert()
        .success();

    let sign_stdout = String::from_utf8(sign_output.get_output().stdout.clone()).unwrap();
    let signature = extract_signature(&sign_stdout);
    let public_key = extract_public_key_from_sign_output(&sign_stdout);

    // Now verify the signature
    let mut verify_cmd = Command::cargo_bin("cli-wallet").unwrap();
    verify_cmd
        .arg("verify")
        .arg("--message")
        .arg(message)
        .arg("--signature")
        .arg(&signature)
        .arg("--public-key")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Signature verification SUCCESSFUL",
        ));
}

/// Test verify command with invalid signature
#[test]
fn test_verify_command_invalid_signature() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("verify")
        .arg("--message")
        .arg("test message")
        .arg("--signature")
        .arg("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        .arg("--public-key")
        .arg("034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff")
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verification FAILED"));
}

/// Test help command
#[test]
fn test_help_command() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "A simple command-line cryptocurrency wallet",
        ))
        .stdout(predicate::str::contains("Usage:"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("generate"))
        .stdout(predicate::str::contains("sign"))
        .stdout(predicate::str::contains("verify"));
}

/// Test no arguments shows help
#[test]
fn test_no_arguments_shows_help() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Simple CLI Wallet"))
        .stdout(predicate::str::contains("USAGE:"));
}

/// Test version command
#[test]
fn test_version_command() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

/// Test invalid command
#[test]
fn test_invalid_command() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("invalid_command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Command line error"));
}

/// Test error handling for missing required arguments
#[test]
fn test_sign_missing_arguments() {
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("sign")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

/// Test error handling for malformed hex inputs
#[test]
fn test_malformed_hex_inputs() {
    // Test malformed private key
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("sign")
        .arg("--message")
        .arg("test")
        .arg("--private-key")
        .arg("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Private key must contain only hex characters",
        ));
}

/// Test performance with multiple operations
#[test]
fn test_performance_multiple_operations() {
    use std::time::Instant;

    let start = Instant::now();

    // Perform multiple generate operations
    for _ in 0..5 {
        let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
        cmd.arg("generate").assert().success();
    }

    let duration = start.elapsed();

    // Should complete 5 generations in reasonable time (less than 5 seconds)
    assert!(
        duration.as_secs() < 5,
        "Multiple operations should complete quickly"
    );
}

// Helper functions to extract data from command output

fn extract_private_key(output: &str) -> String {
    for line in output.lines() {
        if line.contains("Private Key:") {
            if let Some(key_part) = line.split("Private Key:").nth(1) {
                return key_part.trim().to_string();
            }
        }
    }
    String::new()
}

fn extract_public_key(output: &str) -> String {
    for line in output.lines() {
        if line.contains("Public Key:") {
            if let Some(key_part) = line.split("Public Key:").nth(1) {
                return key_part.trim().to_string();
            }
        }
    }
    String::new()
}

fn extract_signature(output: &str) -> String {
    for line in output.lines() {
        if line.contains("Signature:") {
            if let Some(sig_part) = line.split("Signature:").nth(1) {
                return sig_part.trim().to_string();
            }
        }
    }
    String::new()
}

fn extract_public_key_from_sign_output(output: &str) -> String {
    for line in output.lines() {
        if line.contains("The public key:") {
            if let Some(key_part) = line.split("The public key:").nth(1) {
                return key_part.trim().to_string();
            }
        }
    }
    String::new()
}

/// Test edge cases and boundary conditions
#[test]
fn test_edge_cases() {
    // Test with very long message
    let long_message = "a".repeat(1000);
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("sign")
        .arg("--message")
        .arg(&long_message)
        .arg("--private-key")
        .arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .assert()
        .success();

    // Test with message containing special characters
    let special_message = "Hello! @#$%^&*()_+ 🚀 blockchain 世界";
    let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
    cmd.arg("sign")
        .arg("--message")
        .arg(special_message)
        .arg("--private-key")
        .arg("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .assert()
        .success();
}

/// Test concurrent operations (basic stress test)
#[test]
fn test_concurrent_operations() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // Spawn multiple threads to test concurrent wallet generation
    for _ in 0..3 {
        let success_count = Arc::clone(&success_count);
        let handle = thread::spawn(move || {
            let mut cmd = Command::cargo_bin("cli-wallet").unwrap();
            if cmd.arg("generate").assert().try_success().is_ok() {
                success_count.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // All operations should succeed
    assert_eq!(success_count.load(Ordering::SeqCst), 3);
}
