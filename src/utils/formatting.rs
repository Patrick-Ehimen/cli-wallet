//! Formatting utilities for keys, signatures, and addresses
//!
//! This module provides functions for converting cryptographic data structures
//! to and from human-readable formats, primarily hex encoding/decoding.

use crate::error::{WalletError, WalletResult};
use secp256k1::{PublicKey, SecretKey, ecdsa::Signature};

/// Format a private key as a hex string
///
/// Converts a secp256k1 private key to a 64-character hex string.
///
/// # Arguments
///
/// * `private_key` - The private key to format
///
/// # Returns
///
/// * `String` - The hex-encoded private key (64 characters)
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::generate_private_key;
/// use cli_wallet::utils::formatting::format_private_key;
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let hex_string = format_private_key(&private_key);
/// assert_eq!(hex_string.len(), 64);
/// ```
pub fn format_private_key(private_key: &SecretKey) -> String {
    hex::encode(private_key.secret_bytes())
}

/// Parse a private key from a hex string
///
/// Converts a 64-character hex string to a secp256k1 private key.
///
/// # Arguments
///
/// * `hex_str` - The hex string to parse (must be 64 characters)
///
/// # Returns
///
/// * `WalletResult<SecretKey>` - The parsed private key or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::{format_private_key, parse_private_key_hex};
/// use cli_wallet::crypto::generate_private_key;
///
/// let original_key = generate_private_key().expect("Failed to generate key");
/// let hex_string = format_private_key(&original_key);
/// let parsed_key = parse_private_key_hex(&hex_string).expect("Failed to parse");
/// ```
pub fn parse_private_key_hex(hex_str: &str) -> WalletResult<SecretKey> {
    // Validate length (64 hex characters = 32 bytes)
    if hex_str.len() != 64 {
        return Err(WalletError::invalid_input(format!(
            "Private key hex string must be 64 characters, got {}",
            hex_str.len()
        )));
    }

    // Decode hex string to bytes
    let bytes = hex::decode(hex_str)?;

    // Create SecretKey from bytes
    SecretKey::from_slice(&bytes)
        .map_err(|e| WalletError::invalid_input(format!("Invalid private key format: {}", e)))
}

/// Format a public key as a hex string
///
/// Converts a secp256k1 public key to a hex string.
///
/// # Arguments
///
/// * `public_key` - The public key to format
/// * `compressed` - Whether to use compressed format (33 bytes) or uncompressed (65 bytes)
///
/// # Returns
///
/// * `String` - The hex-encoded public key
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{generate_private_key, derive_public_key};
/// use cli_wallet::utils::formatting::format_public_key;
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
/// let compressed_hex = format_public_key(&public_key, true);
/// let uncompressed_hex = format_public_key(&public_key, false);
/// ```
pub fn format_public_key(public_key: &PublicKey, compressed: bool) -> String {
    if compressed {
        hex::encode(public_key.serialize())
    } else {
        hex::encode(public_key.serialize_uncompressed())
    }
}

/// Parse a public key from a hex string
///
/// Converts a hex string to a secp256k1 public key.
/// Supports both compressed (66 chars) and uncompressed (130 chars) formats.
///
/// # Arguments
///
/// * `hex_str` - The hex string to parse
///
/// # Returns
///
/// * `WalletResult<PublicKey>` - The parsed public key or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::{format_public_key, parse_public_key_hex};
/// use cli_wallet::crypto::{generate_private_key, derive_public_key};
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let original_key = derive_public_key(&private_key).expect("Failed to derive public key");
/// let hex_string = format_public_key(&original_key, true);
/// let parsed_key = parse_public_key_hex(&hex_string).expect("Failed to parse");
/// ```
pub fn parse_public_key_hex(hex_str: &str) -> WalletResult<PublicKey> {
    // Validate length (66 chars for compressed, 130 for uncompressed)
    if hex_str.len() != 66 && hex_str.len() != 130 {
        return Err(WalletError::invalid_input(format!(
            "Public key hex string must be 66 (compressed) or 130 (uncompressed) characters, got {}",
            hex_str.len()
        )));
    }

    // Decode hex string to bytes
    let bytes = hex::decode(hex_str)?;

    // Create PublicKey from bytes
    PublicKey::from_slice(&bytes)
        .map_err(|e| WalletError::invalid_input(format!("Invalid public key format: {}", e)))
}

/// Format a signature as a hex string
///
/// Converts a secp256k1 signature to a 128-character hex string.
///
/// # Arguments
///
/// * `signature` - The signature to format
///
/// # Returns
///
/// * `String` - The hex-encoded signature (128 characters)
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{generate_private_key, sign_message};
/// use cli_wallet::utils::formatting::format_signature;
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let message = b"Hello, world!";
/// let signature = sign_message(message, &private_key).expect("Failed to sign");
/// let hex_string = format_signature(&signature);
/// assert_eq!(hex_string.len(), 128);
/// ```
pub fn format_signature(signature: &Signature) -> String {
    hex::encode(signature.serialize_compact())
}

/// Parse a signature from a hex string
///
/// Converts a 128-character hex string to a secp256k1 signature.
///
/// # Arguments
///
/// * `hex_str` - The hex string to parse (must be 128 characters)
///
/// # Returns
///
/// * `WalletResult<Signature>` - The parsed signature or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::{format_signature, parse_signature_hex};
/// use cli_wallet::crypto::{generate_private_key, sign_message};
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let message = b"Hello, world!";
/// let signature = sign_message(message, &private_key).expect("Failed to sign");
/// let hex_string = format_signature(&signature);
/// let parsed_signature = parse_signature_hex(&hex_string).expect("Failed to parse");
/// ```
pub fn parse_signature_hex(hex_str: &str) -> WalletResult<Signature> {
    // Check length (128 hex characters = 64 bytes)
    if hex_str.len() != 128 {
        return Err(WalletError::invalid_input(format!(
            "Signature hex string must be 128 characters, got {}",
            hex_str.len()
        )));
    }

    // Decode hex string to bytes
    let bytes = hex::decode(hex_str)?;

    // Create Signature from bytes
    Signature::from_compact(&bytes)
        .map_err(|e| WalletError::invalid_input(format!("Invalid signature format: {}", e)))
}

/// Format an address as a hex string
///
/// Converts address bytes to a hex string with optional prefix.
///
/// # Arguments
///
/// * `address_bytes` - The address bytes to format
/// * `with_prefix` - Whether to include "0x" prefix
///
/// # Returns
///
/// * `String` - The hex-encoded address
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::format_address;
///
/// let address_bytes = [0u8; 20]; // Example 20-byte address
/// let hex_address = format_address(&address_bytes, true);
/// assert!(hex_address.starts_with("0x"));
/// ```
pub fn format_address(address_bytes: &[u8], with_prefix: bool) -> String {
    let hex_string = hex::encode(address_bytes);
    if with_prefix {
        format!("0x{}", hex_string)
    } else {
        hex_string
    }
}

/// Parse an address from a hex string
///
/// Converts a hex string to address bytes, handling optional "0x" prefix.
///
/// # Arguments
///
/// * `hex_str` - The hex string to parse (with or without "0x" prefix)
///
/// # Returns
///
/// * `WalletResult<Vec<u8>>` - The parsed address bytes or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::{format_address, parse_address_hex};
///
/// let address_bytes = [0u8; 20];
/// let hex_string = format_address(&address_bytes, true);
/// let parsed_bytes = parse_address_hex(&hex_string).expect("Failed to parse");
/// assert_eq!(address_bytes.to_vec(), parsed_bytes);
/// ```
pub fn parse_address_hex(hex_str: &str) -> WalletResult<Vec<u8>> {
    // Remove "0x" prefix if present
    let clean_hex = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        &hex_str[2..]
    } else {
        hex_str
    };

    // Validate that we have an even number of characters
    if clean_hex.len() % 2 != 0 {
        return Err(WalletError::invalid_input(
            "Address hex string must have even number of characters".to_string(),
        ));
    }

    // Decode hex string to bytes
    hex::decode(clean_hex)
        .map_err(|e| WalletError::invalid_input(format!("Invalid address hex format: {}", e)))
}

/// Display formatting for keys with labels
///
/// Creates a formatted display string for keys with descriptive labels.
///
/// # Arguments
///
/// * `label` - The label to display (e.g., "Private Key", "Public Key")
/// * `value` - The hex-encoded value to display
/// * `truncate` - Whether to truncate long values for display
///
/// # Returns
///
/// * `String` - The formatted display string
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::format_key_display;
///
/// let display = format_key_display("Private Key", "abcd1234...", false);
/// assert!(display.contains("Private Key"));
/// assert!(display.contains("abcd1234"));
/// ```
pub fn format_key_display(label: &str, value: &str, truncate: bool) -> String {
    if truncate && value.len() > 16 {
        format!("{}: {}...{}", label, &value[..8], &value[value.len() - 8..])
    } else {
        format!("{}: {}", label, value)
    }
}

/// Display formatting for addresses with checksums
///
/// Creates a formatted display string for addresses with optional checksum validation.
///
/// # Arguments
///
/// * `address` - The address hex string
/// * `with_checksum` - Whether to include checksum information
///
/// # Returns
///
/// * `String` - The formatted address display string
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::format_address_display;
///
/// let display = format_address_display("0x1234567890abcdef", false);
/// assert!(display.contains("0x1234567890abcdef"));
/// ```
pub fn format_address_display(address: &str, with_checksum: bool) -> String {
    if with_checksum {
        format!("Address: {} (with checksum)", address)
    } else {
        format!("Address: {}", address)
    }
}

/// Utility function to validate hex string format
///
/// Checks if a string contains only valid hexadecimal characters.
///
/// # Arguments
///
/// * `hex_str` - The string to validate
///
/// # Returns
///
/// * `bool` - True if valid hex, false otherwise
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::is_valid_hex;
///
/// assert!(is_valid_hex("abcdef123456"));
/// assert!(!is_valid_hex("ghijkl"));
/// ```
pub fn is_valid_hex(hex_str: &str) -> bool {
    hex_str.chars().all(|c| c.is_ascii_hexdigit())
}

/// Utility function to normalize hex strings
///
/// Removes common prefixes and converts to lowercase.
///
/// # Arguments
///
/// * `hex_str` - The hex string to normalize
///
/// # Returns
///
/// * `String` - The normalized hex string
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::formatting::normalize_hex;
///
/// assert_eq!(normalize_hex("0xABCD"), "abcd");
/// assert_eq!(normalize_hex("0XABCD"), "abcd");
/// assert_eq!(normalize_hex("ABCD"), "abcd");
/// ```
pub fn normalize_hex(hex_str: &str) -> String {
    let clean = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        &hex_str[2..]
    } else {
        hex_str
    };
    clean.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_public_key, generate_private_key, sign_message};
    use std::str::FromStr;

    #[test]
    fn test_format_private_key() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let hex_string = format_private_key(&private_key);

        assert_eq!(
            hex_string.len(),
            64,
            "Private key hex should be 64 characters"
        );
        assert!(is_valid_hex(&hex_string), "Should be valid hex");
    }

    #[test]
    fn test_parse_private_key_hex_valid() {
        let original_key = generate_private_key().expect("Failed to generate private key");
        let hex_string = format_private_key(&original_key);
        let parsed_key = parse_private_key_hex(&hex_string).expect("Failed to parse private key");

        assert_eq!(
            original_key.secret_bytes(),
            parsed_key.secret_bytes(),
            "Parsed key should match original"
        );
    }

    #[test]
    fn test_parse_private_key_hex_invalid_length() {
        let short_hex = "1234567890abcdef";
        let result = parse_private_key_hex(short_hex);
        assert!(result.is_err(), "Short hex should fail");

        let long_hex = "1234567890abcdef".repeat(5);
        let result = parse_private_key_hex(&long_hex);
        assert!(result.is_err(), "Long hex should fail");
    }

    #[test]
    fn test_parse_private_key_hex_invalid_hex() {
        let invalid_hex = "g".repeat(64);
        let result = parse_private_key_hex(&invalid_hex);
        assert!(result.is_err(), "Invalid hex characters should fail");
    }

    #[test]
    fn test_format_public_key_compressed() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");

        let compressed_hex = format_public_key(&public_key, true);
        let uncompressed_hex = format_public_key(&public_key, false);

        assert_eq!(
            compressed_hex.len(),
            66,
            "Compressed public key should be 66 characters"
        );
        assert_eq!(
            uncompressed_hex.len(),
            130,
            "Uncompressed public key should be 130 characters"
        );
        assert!(compressed_hex.starts_with("02") || compressed_hex.starts_with("03"));
        assert!(uncompressed_hex.starts_with("04"));
    }

    #[test]
    fn test_parse_public_key_hex_compressed() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let original_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let hex_string = format_public_key(&original_key, true);
        let parsed_key = parse_public_key_hex(&hex_string).expect("Failed to parse public key");

        assert_eq!(
            original_key.serialize(),
            parsed_key.serialize(),
            "Parsed compressed key should match original"
        );
    }

    #[test]
    fn test_parse_public_key_hex_uncompressed() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let original_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let hex_string = format_public_key(&original_key, false);
        let parsed_key = parse_public_key_hex(&hex_string).expect("Failed to parse public key");

        assert_eq!(
            original_key.serialize_uncompressed(),
            parsed_key.serialize_uncompressed(),
            "Parsed uncompressed key should match original"
        );
    }

    #[test]
    fn test_parse_public_key_hex_invalid_length() {
        let invalid_hex = "1234567890abcdef";
        let result = parse_public_key_hex(invalid_hex);
        assert!(result.is_err(), "Invalid length should fail");
    }

    #[test]
    fn test_format_signature() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = b"Test message";
        let signature = sign_message(message, &private_key).expect("Failed to sign message");

        let hex_string = format_signature(&signature);
        assert_eq!(
            hex_string.len(),
            128,
            "Signature hex should be 128 characters"
        );
        assert!(is_valid_hex(&hex_string), "Should be valid hex");
    }

    #[test]
    fn test_parse_signature_hex_valid() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = b"Test message";
        let original_signature =
            sign_message(message, &private_key).expect("Failed to sign message");
        let hex_string = format_signature(&original_signature);
        let parsed_signature = parse_signature_hex(&hex_string).expect("Failed to parse signature");

        assert_eq!(
            original_signature.serialize_compact(),
            parsed_signature.serialize_compact(),
            "Parsed signature should match original"
        );
    }

    #[test]
    fn test_parse_signature_hex_invalid_length() {
        let short_hex = "1234567890abcdef";
        let result = parse_signature_hex(short_hex);
        assert!(result.is_err(), "Short hex should fail");

        let long_hex = "1234567890abcdef".repeat(10);
        let result = parse_signature_hex(&long_hex);
        assert!(result.is_err(), "Long hex should fail");
    }

    #[test]
    fn test_format_address_with_prefix() {
        let address_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];

        let with_prefix = format_address(&address_bytes, true);
        let without_prefix = format_address(&address_bytes, false);

        assert!(with_prefix.starts_with("0x"), "Should have 0x prefix");
        assert!(
            !without_prefix.starts_with("0x"),
            "Should not have 0x prefix"
        );
        assert_eq!(with_prefix.len(), 42, "With prefix should be 42 characters");
        assert_eq!(
            without_prefix.len(),
            40,
            "Without prefix should be 40 characters"
        );
    }

    #[test]
    fn test_parse_address_hex_with_prefix() {
        let address_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];
        let hex_with_prefix = format_address(&address_bytes, true);
        let hex_without_prefix = format_address(&address_bytes, false);

        let parsed_with_prefix =
            parse_address_hex(&hex_with_prefix).expect("Failed to parse with prefix");
        let parsed_without_prefix =
            parse_address_hex(&hex_without_prefix).expect("Failed to parse without prefix");

        assert_eq!(address_bytes.to_vec(), parsed_with_prefix);
        assert_eq!(address_bytes.to_vec(), parsed_without_prefix);
    }

    #[test]
    fn test_parse_address_hex_odd_length() {
        let odd_hex = "0x123";
        let result = parse_address_hex(odd_hex);
        assert!(result.is_err(), "Odd length hex should fail");
    }

    #[test]
    fn test_format_key_display() {
        let long_key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let truncated = format_key_display("Private Key", long_key, true);
        let full = format_key_display("Private Key", long_key, false);

        assert!(
            truncated.contains("12345678...90abcdef"),
            "Should be truncated"
        );
        assert!(full.contains(long_key), "Should contain full key");
        assert!(truncated.contains("Private Key"), "Should contain label");
        assert!(full.contains("Private Key"), "Should contain label");
    }

    #[test]
    fn test_format_address_display() {
        let address = "0x1234567890abcdef1234567890abcdef12345678";

        let with_checksum = format_address_display(address, true);
        let without_checksum = format_address_display(address, false);

        assert!(
            with_checksum.contains("with checksum"),
            "Should mention checksum"
        );
        assert!(
            !without_checksum.contains("checksum"),
            "Should not mention checksum"
        );
        assert!(with_checksum.contains(address), "Should contain address");
        assert!(without_checksum.contains(address), "Should contain address");
    }

    #[test]
    fn test_is_valid_hex() {
        assert!(is_valid_hex("abcdef123456"), "Valid hex should return true");
        assert!(
            is_valid_hex("ABCDEF123456"),
            "Uppercase hex should return true"
        );
        assert!(
            is_valid_hex("0123456789abcdefABCDEF"),
            "Mixed case hex should return true"
        );
        assert!(
            !is_valid_hex("ghijkl"),
            "Invalid characters should return false"
        );
        assert!(
            !is_valid_hex("123g456"),
            "Mixed valid/invalid should return false"
        );
        assert!(is_valid_hex(""), "Empty string should return true");
    }

    #[test]
    fn test_normalize_hex() {
        assert_eq!(normalize_hex("0xABCD"), "abcd");
        assert_eq!(normalize_hex("0XABCD"), "abcd");
        assert_eq!(normalize_hex("ABCD"), "abcd");
        assert_eq!(normalize_hex("abcd"), "abcd");
        assert_eq!(normalize_hex("0x"), "");
    }

    #[test]
    fn test_round_trip_private_key() {
        let original_key = generate_private_key().expect("Failed to generate private key");
        let hex_string = format_private_key(&original_key);
        let parsed_key = parse_private_key_hex(&hex_string).expect("Failed to parse private key");
        let hex_string2 = format_private_key(&parsed_key);

        assert_eq!(
            hex_string, hex_string2,
            "Round trip should preserve hex string"
        );
    }

    #[test]
    fn test_round_trip_public_key() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let original_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let hex_string = format_public_key(&original_key, true);
        let parsed_key = parse_public_key_hex(&hex_string).expect("Failed to parse public key");
        let hex_string2 = format_public_key(&parsed_key, true);

        assert_eq!(
            hex_string, hex_string2,
            "Round trip should preserve hex string"
        );
    }

    #[test]
    fn test_round_trip_signature() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = b"Test message";
        let original_signature =
            sign_message(message, &private_key).expect("Failed to sign message");
        let hex_string = format_signature(&original_signature);
        let parsed_signature = parse_signature_hex(&hex_string).expect("Failed to parse signature");
        let hex_string2 = format_signature(&parsed_signature);

        assert_eq!(
            hex_string, hex_string2,
            "Round trip should preserve hex string"
        );
    }

    #[test]
    fn test_round_trip_address() {
        let address_bytes = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];
        let hex_string = format_address(&address_bytes, true);
        let parsed_bytes = parse_address_hex(&hex_string).expect("Failed to parse address");
        let hex_string2 = format_address(&parsed_bytes, true);

        assert_eq!(
            hex_string, hex_string2,
            "Round trip should preserve hex string"
        );
    }

    #[test]
    fn test_deterministic_formatting() {
        // Test with known private key for deterministic results
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key = SecretKey::from_str(private_key_hex).expect("Failed to create test key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");

        let formatted_private = format_private_key(&private_key);
        let formatted_public = format_public_key(&public_key, true);

        assert_eq!(formatted_private, private_key_hex);
        assert_eq!(formatted_public.len(), 66);

        // Should be deterministic
        let formatted_private2 = format_private_key(&private_key);
        let formatted_public2 = format_public_key(&public_key, true);

        assert_eq!(formatted_private, formatted_private2);
        assert_eq!(formatted_public, formatted_public2);
    }
}
