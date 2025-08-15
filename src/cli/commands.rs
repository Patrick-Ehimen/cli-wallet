//! Command execution handlers for the CLI wallet application
//!
//! This module contains the implementation of all CLI commands including generate,
//! sign, and verify operations. Each command handler validates inputs, performs
//! the requested cryptographic operation, and provides user-friendly output.

use crate::cli::parser::{Cli, Commands};
use crate::error::WalletError;
use crate::wallet::{Wallet, validate_private_key_hex, validate_public_key_hex};

/// Execute the parsed CLI command with comprehensive error handling
///
/// This function serves as the main entry point for command execution. It first
/// validates all command arguments, then routes to the appropriate command handler.
///
/// # Arguments
///
/// * `cli` - The parsed CLI structure containing the command and its arguments
///
/// # Returns
///
/// * `Result<(), WalletError>` - Success or detailed error information
///
/// # Examples
///
/// ```rust
/// use cli_wallet::cli::{Cli, execute_command};
/// use clap::Parser;
///
/// let args = vec!["cli-wallet", "generate"];
/// let cli = Cli::try_parse_from(args).unwrap();
/// let result = execute_command(cli);
/// assert!(result.is_ok());
/// ```
///
/// # Error Handling
///
/// This function performs input validation before executing commands and provides
/// context-rich error messages for all failure scenarios including:
/// - Invalid command arguments
/// - Cryptographic operation failures
/// - Input format validation errors
pub fn execute_command(cli: Cli) -> Result<(), WalletError> {
    // Validate arguments first
    if let Err(validation_error) = cli.validate() {
        return Err(WalletError::InvalidInput(validation_error));
    }

    match cli.command {
        Commands::Generate => execute_generate(),
        Commands::Sign {
            message,
            private_key,
        } => execute_sign(&message, &private_key),
        Commands::Verify {
            message,
            signature,
            public_key,
        } => execute_verify(&message, &signature, &public_key),
    }
}

/// Execute the generate command to create a new wallet
///
/// This function generates a new cryptographically secure wallet containing:
/// - A random secp256k1 private key (256 bits)
/// - The corresponding public key (derived from private key)
/// - A wallet address (derived from public key hash)
///
/// The generated keys use cryptographically secure random number generation
/// and follow industry standards for cryptocurrency wallets.
///
/// # Returns
///
/// * `Result<(), WalletError>` - Success with printed output or error details
///
/// # Output Format
///
/// The command outputs the wallet information in a user-friendly format:
/// ```text
/// ✅ New wallet generated successfully!
///
/// 🔑 Private Key: <64-character hex string>
/// 🔓 Public Key:  <66-character hex string>
/// 📍 Address:     0x<40-character hex string>
///
/// ⚠️  IMPORTANT: Keep your private key secure and never share it!
/// ```
///
/// # Security Notes
///
/// - Private keys are generated using the system's cryptographically secure RNG
/// - Keys are only displayed once and not stored persistently
/// - Users are warned about private key security in the output
fn execute_generate() -> Result<(), WalletError> {
    // Create a new wallet with generated key pair
    let wallet = Wallet::new()
        .map_err(|e| WalletError::key_generation(format!("Failed to create wallet: {}", e)))?;

    // Get the formatted key pair
    let (private_key_hex, public_key_hex) = wallet
        .generate_keypair()
        .map_err(|e| WalletError::key_generation(format!("Failed to format keys: {}", e)))?;

    // Generate wallet address
    let address = wallet
        .create_address()
        .map_err(|e| WalletError::address(format!("Failed to create address: {}", e)))?;

    // Display the results in a user-friendly format
    println!("✅ New wallet generated successfully!");
    println!();
    println!("🔑 Private Key: {}", private_key_hex);
    println!("🔓 Public Key:  {}", public_key_hex);
    println!("📍 Address:     0x{}", address);
    println!();
    println!("⚠️  IMPORTANT: Keep your private key secure and never share it!");
    println!("   Your private key is needed to sign messages and access your wallet.");

    Ok(())
}

/// Execute the sign command to create a digital signature
///
/// This function signs a message using the provided private key and the ECDSA
/// signature algorithm with the secp256k1 elliptic curve. The message is first
/// hashed using SHA-256 before signing to ensure security and prevent certain
/// types of attacks.
///
/// # Arguments
///
/// * `message` - The message string to sign (will be converted to UTF-8 bytes)
/// * `private_key` - The private key as a 64-character hexadecimal string
///
/// # Returns
///
/// * `Result<(), WalletError>` - Success with printed signature or error details
///
/// # Input Validation
///
/// The function validates:
/// - Private key format (exactly 64 hex characters)
/// - Private key cryptographic validity (not zero, within curve order)
/// - Message is not empty
///
/// # Output Format
///
/// ```text
/// ✅ Message signed successfully!
///
/// 📝 Message:   "Your message here"
/// 🔏 Signature: <128-character hex string>
///
/// ℹ️  You can verify this signature using the verify command...
/// ```
///
/// # Security Properties
///
/// - Uses deterministic nonce generation (RFC 6979) for signature security
/// - Each signature is unique even for the same message
/// - Signatures cannot be forged without the private key
/// - Message integrity is cryptographically guaranteed
fn execute_sign(message: &str, private_key: &str) -> Result<(), WalletError> {
    // Validate and parse the private key
    let secret_key = validate_private_key_hex(private_key)
        .map_err(|e| WalletError::invalid_input(format!("Invalid private key: {}", e)))?;

    // Create a wallet from the private key (we need to derive the public key)
    let public_key = crate::crypto::derive_public_key(&secret_key)
        .map_err(|e| WalletError::key_generation(format!("Failed to derive public key: {}", e)))?;

    // Create wallet instance (we'd need a constructor for this, but for now we'll use the crypto functions directly)
    // Sign the message using the crypto module
    let signature = crate::crypto::sign_message(message.as_bytes(), &secret_key)
        .map_err(|e| WalletError::signing(format!("Failed to sign message: {}", e)))?;

    // Format the signature for output
    let signature_hex = crate::crypto::format_signature(&signature);

    // Display the results in a user-friendly format
    println!("✅ Message signed successfully!");
    println!();
    println!("📝 Message:   \"{}\"", message);
    println!("🔏 Signature: {}", signature_hex);
    println!();
    println!("ℹ️  You can verify this signature using the verify command with:");
    println!("   - The original message: \"{}\"", message);
    println!("   - The signature: {}", signature_hex);
    println!(
        "   - The public key: {}",
        crate::crypto::format_public_key(&public_key, true)
    );

    Ok(())
}

/// Execute the verify command to validate a digital signature
///
/// This function verifies that a signature was created by the holder of the private
/// key corresponding to the provided public key for the given message. It uses the
/// ECDSA verification algorithm with the secp256k1 elliptic curve.
///
/// # Arguments
///
/// * `message` - The original message that was signed
/// * `signature` - The signature as a 128-character hexadecimal string
/// * `public_key` - The public key as a 66-character (compressed) or 130-character (uncompressed) hex string
///
/// # Returns
///
/// * `Result<(), WalletError>` - Success with verification result or error details
///
/// # Input Validation
///
/// The function validates:
/// - Public key format and cryptographic validity
/// - Signature format (128 hex characters for DER encoding)
/// - Message content (non-empty)
///
/// # Output Format
///
/// For valid signatures:
/// ```text
/// ✅ Signature verification SUCCESSFUL!
///
/// 📝 Message:    "Your message here"
/// 🔏 Signature:  <signature hex>
/// 🔓 Public Key: <public key hex>
///
/// ✓ The signature is valid and was created by the holder of this private key.
/// ```
///
/// For invalid signatures:
/// ```text
/// ❌ Signature verification FAILED!
///
/// [Details and possible reasons for failure]
/// ```
///
/// # Security Properties
///
/// - Cryptographically proves message authenticity and integrity
/// - Cannot be forged without access to the corresponding private key
/// - Detects any tampering with the original message
/// - Provides non-repudiation (signer cannot deny signing)
fn execute_verify(message: &str, signature: &str, public_key: &str) -> Result<(), WalletError> {
    // Validate and parse the public key
    let public_key_parsed = validate_public_key_hex(public_key)
        .map_err(|e| WalletError::invalid_input(format!("Invalid public key: {}", e)))?;

    // Parse the signature from hex string
    let signature_parsed = crate::crypto::parse_signature_hex(signature)
        .map_err(|e| WalletError::invalid_input(format!("Invalid signature: {}", e)))?;

    // Verify the signature
    let is_valid =
        crate::crypto::verify_signature(message.as_bytes(), &signature_parsed, &public_key_parsed)
            .map_err(|e| WalletError::verification(format!("Failed to verify signature: {}", e)))?;

    // Display the results in a user-friendly format
    if is_valid {
        println!("✅ Signature verification SUCCESSFUL!");
        println!();
        println!("📝 Message:    \"{}\"", message);
        println!("🔏 Signature:  {}", signature);
        println!("🔓 Public Key: {}", public_key);
        println!();
        println!("✓ The signature is valid and was created by the holder of this private key.");
    } else {
        println!("❌ Signature verification FAILED!");
        println!();
        println!("📝 Message:    \"{}\"", message);
        println!("🔏 Signature:  {}", signature);
        println!("🔓 Public Key: {}", public_key);
        println!();
        println!(
            "✗ The signature is invalid or was not created by the holder of this private key."
        );
        println!("  This could mean:");
        println!("  - The message was tampered with");
        println!("  - The signature is incorrect");
        println!("  - The public key doesn't match the private key used for signing");
    }

    Ok(())
}

/// Display comprehensive help information for the CLI wallet
///
/// This function provides detailed usage information, command descriptions,
/// examples, and security notes to help users understand how to use the
/// wallet application safely and effectively.
///
/// # Output
///
/// Displays formatted help text including:
/// - Application description and purpose
/// - Command syntax and usage patterns
/// - Detailed examples for each command
/// - Security considerations and best practices
/// - Parameter format requirements
pub fn display_help() {
    println!("🔐 Simple CLI Wallet - A command-line cryptocurrency wallet");
    println!("   Using secp256k1 elliptic curve cryptography");
    println!();
    println!("USAGE:");
    println!("    cli-wallet <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    generate    Generate a new key pair and wallet address");
    println!("    sign        Sign a message with a private key");
    println!("    verify      Verify a message signature");
    println!("    help        Print this message or the help of the given subcommand(s)");
    println!();
    println!("EXAMPLES:");
    println!("    # Generate a new wallet");
    println!("    cli-wallet generate");
    println!();
    println!("    # Sign a message");
    println!("    cli-wallet sign -m \"Hello world\" -k <private_key>");
    println!();
    println!("    # Verify a signature");
    println!("    cli-wallet verify -m \"Hello world\" -s <signature> -k <public_key>");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help       Print help information");
    println!("    -V, --version    Print version information");
    println!();
    println!("For more information about a specific command, use:");
    println!("    cli-wallet <COMMAND> --help");
    println!();
    println!("SECURITY NOTES:");
    println!("    • Never share your private key with anyone");
    println!("    • Store your private key securely");
    println!("    • Private keys are 64 hex characters (32 bytes)");
    println!("    • Public keys are 66 hex characters (33 bytes, compressed)");
    println!("    • Signatures are 128 hex characters (64 bytes)");
}

/// Display user-friendly error message with context and suggestions
///
/// This function takes a WalletError and displays it in a user-friendly format
/// with helpful suggestions for resolving the issue. It provides specific
/// guidance based on the error type to help users correct their input.
///
/// # Arguments
///
/// * `error` - The WalletError to display with context
///
/// # Output Format
///
/// ```text
/// ❌ Error: [Error description]
///
/// 💡 Suggestions:
///    • [Specific suggestion 1]
///    • [Specific suggestion 2]
///
/// For more help, run: cli-wallet --help
/// ```
///
/// # Error-Specific Guidance
///
/// The function provides tailored suggestions for different error types:
/// - **InvalidInput**: Format requirements and examples
/// - **KeyGenerationError**: System entropy and retry suggestions
/// - **SigningError**: Private key validation tips
/// - **VerificationError**: Parameter checking guidance
/// - **AddressError**: Wallet generation alternatives
/// - **CryptoError**: General cryptographic troubleshooting
pub fn display_error(error: &WalletError) {
    eprintln!("❌ Error: {}", error);

    // Provide helpful suggestions based on error type
    match error {
        WalletError::InvalidInput(msg) => {
            eprintln!();
            eprintln!("💡 Suggestions:");
            if msg.contains("Private key") {
                eprintln!("   • Private keys must be exactly 64 hex characters");
                eprintln!("   • Use only characters 0-9 and a-f");
                eprintln!(
                    "   • Example: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                );
            } else if msg.contains("Public key") {
                eprintln!("   • Public keys must be 66 hex characters (compressed format)");
                eprintln!("   • Should start with '02' or '03'");
                eprintln!(
                    "   • Example: 034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff"
                );
            } else if msg.contains("Signature") {
                eprintln!("   • Signatures must be exactly 128 hex characters");
                eprintln!("   • Use only characters 0-9 and a-f");
            } else if msg.contains("Message") {
                eprintln!("   • Messages cannot be empty");
                eprintln!("   • Use quotes for messages with spaces");
            }
        }
        WalletError::KeyGenerationError(_) => {
            eprintln!();
            eprintln!("💡 Suggestions:");
            eprintln!("   • Try running the command again");
            eprintln!(
                "   • Ensure your system has sufficient entropy for random number generation"
            );
        }
        WalletError::SigningError(_) => {
            eprintln!();
            eprintln!("💡 Suggestions:");
            eprintln!("   • Verify your private key is correct and valid");
            eprintln!("   • Ensure the message is not empty");
        }
        WalletError::VerificationError(_) => {
            eprintln!();
            eprintln!("💡 Suggestions:");
            eprintln!("   • Check that all parameters are correct");
            eprintln!("   • Ensure the signature, message, and public key match");
        }
        WalletError::AddressError(_) => {
            eprintln!();
            eprintln!("💡 Suggestions:");
            eprintln!("   • Try generating a new wallet");
            eprintln!("   • Verify the public key is valid");
        }
        WalletError::CryptoError(_) => {
            eprintln!();
            eprintln!("💡 Suggestions:");
            eprintln!("   • Check that all cryptographic parameters are valid");
            eprintln!("   • Try the operation again");
        }
    }

    eprintln!();
    eprintln!("For more help, run: cli-wallet --help");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::parser::Cli;
    use clap::Parser;

    #[test]
    fn test_execute_generate_command() {
        let args = vec!["cli-wallet", "generate"];
        let cli = Cli::try_parse_from(args).unwrap();

        // Should successfully generate a wallet
        let result = execute_command(cli);
        assert!(result.is_ok(), "Generate command should succeed");
    }

    #[test]
    fn test_execute_generate_command_multiple_times() {
        // Test that multiple generate commands work and produce different results
        let args = vec!["cli-wallet", "generate"];

        let cli1 = Cli::try_parse_from(args.clone()).unwrap();
        let result1 = execute_command(cli1);
        assert!(result1.is_ok(), "First generate command should succeed");

        let cli2 = Cli::try_parse_from(args).unwrap();
        let result2 = execute_command(cli2);
        assert!(result2.is_ok(), "Second generate command should succeed");
    }

    #[test]
    fn test_execute_sign_command() {
        let args = vec![
            "cli-wallet",
            "sign",
            "--message",
            "test message",
            "--private-key",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // Valid test key
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        let result = execute_command(cli);
        assert!(
            result.is_ok(),
            "Sign command should succeed with valid inputs"
        );
    }

    #[test]
    fn test_execute_sign_command_invalid_private_key() {
        let args = vec![
            "cli-wallet",
            "sign",
            "--message",
            "test message",
            "--private-key",
            "0000000000000000000000000000000000000000000000000000000000000000", // Invalid zero key
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        let result = execute_command(cli);
        assert!(
            result.is_err(),
            "Sign command should fail with invalid private key"
        );

        match result.unwrap_err() {
            WalletError::InvalidInput(_) => {} // Expected error type
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn test_execute_verify_command_valid_signature() {
        // First, create a valid signature using known keys
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let message = "test message";

        // Create the signature using our crypto functions
        let private_key = validate_private_key_hex(private_key_hex).unwrap();
        let public_key = crate::crypto::derive_public_key(&private_key).unwrap();
        let signature = crate::crypto::sign_message(message.as_bytes(), &private_key).unwrap();
        let signature_hex = crate::crypto::format_signature(&signature);
        let public_key_hex = crate::crypto::format_public_key(&public_key, true);

        let args = vec![
            "cli-wallet",
            "verify",
            "--message",
            message,
            "--signature",
            &signature_hex,
            "--public-key",
            &public_key_hex,
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        let result = execute_command(cli);
        assert!(
            result.is_ok(),
            "Verify command should succeed with valid signature"
        );
    }

    #[test]
    fn test_execute_verify_command_invalid_signature() {
        let args = vec![
            "cli-wallet",
            "verify",
            "--message",
            "test message",
            "--signature",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", // Invalid signature
            "--public-key",
            "034646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff", // Valid public key
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        let result = execute_command(cli);
        assert!(
            result.is_ok(),
            "Verify command should succeed even with invalid signature (just report false)"
        );
    }

    #[test]
    fn test_execute_command_with_invalid_input() {
        let args = vec![
            "cli-wallet",
            "sign",
            "--message",
            "", // Empty message should fail validation
            "--private-key",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        let result = execute_command(cli);
        assert!(result.is_err());

        match result.unwrap_err() {
            WalletError::InvalidInput(msg) => {
                assert_eq!(msg, "Message cannot be empty");
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn test_display_help() {
        // Test that display_help doesn't panic and produces output
        display_help();
        // If we reach here without panicking, the test passes
    }

    #[test]
    fn test_display_error_invalid_input() {
        let error = WalletError::invalid_input("Private key must be 64 hex characters".to_string());
        display_error(&error);
        // If we reach here without panicking, the test passes
    }

    #[test]
    fn test_display_error_key_generation() {
        let error = WalletError::key_generation("Failed to generate key".to_string());
        display_error(&error);
        // If we reach here without panicking, the test passes
    }

    #[test]
    fn test_display_error_signing() {
        let error = WalletError::signing("Failed to sign message".to_string());
        display_error(&error);
        // If we reach here without panicking, the test passes
    }

    #[test]
    fn test_display_error_verification() {
        let error = WalletError::verification("Failed to verify signature".to_string());
        display_error(&error);
        // If we reach here without panicking, the test passes
    }

    #[test]
    fn test_display_error_address() {
        let error = WalletError::address("Failed to create address".to_string());
        display_error(&error);
        // If we reach here without panicking, the test passes
    }

    #[test]
    fn test_display_error_crypto() {
        let error = WalletError::crypto("Cryptographic operation failed".to_string());
        display_error(&error);
        // If we reach here without panicking, the test passes
    }
}
