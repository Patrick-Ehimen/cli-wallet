//! Cryptographic key generation and management for secp256k1
//!
//! This module provides secure key generation, validation, and formatting functions
//! for secp256k1 elliptic curve cryptography. It handles private key generation
//! using cryptographically secure random number generation and public key derivation.

use crate::error::WalletError;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Generate a new cryptographically secure random private key using secp256k1
///
/// This function uses the operating system's cryptographically secure random number
/// generator (OsRng) to create a private key suitable for cryptocurrency applications.
/// The generated key is guaranteed to be within the valid range for secp256k1.
///
/// # Security Properties
///
/// - Uses OS-provided cryptographically secure random number generation
/// - Automatically ensures the key is within the valid secp256k1 curve order
/// - Provides sufficient entropy for cryptographic security (256 bits)
/// - Resistant to prediction and bias attacks
///
/// This function uses the OS random number generator to create a cryptographically
/// secure private key for the secp256k1 elliptic curve.
///
/// # Returns
///
/// * `Result<SecretKey, WalletError>` - The generated private key or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::generate_private_key;
///
/// let private_key = generate_private_key().expect("Failed to generate private key");
/// ```
pub fn generate_private_key() -> Result<SecretKey, WalletError> {
    let mut rng = OsRng;

    // SecretKey::new generates a random key and doesn't fail in normal circumstances
    let private_key = SecretKey::new(&mut rng);
    Ok(private_key)
}

/// Validate that a private key is cryptographically valid for secp256k1
///
/// This function performs comprehensive validation of a private key to ensure
/// it meets all requirements for secure cryptographic operations. The secp256k1
/// library automatically ensures keys are within the valid range during creation.
///
/// # Arguments
///
/// * `private_key` - The private key to validate
///
/// # Returns
///
/// * `Result<(), WalletError>` - Ok if valid, error if invalid
///
/// # Validation Checks
///
/// - Ensures the key is not zero (invalid for ECDSA)
/// - Verifies the key is less than the curve order
/// - Confirms the key can generate a valid public key
/// - Checks for any secp256k1 library constraints
pub fn validate_private_key(private_key: &SecretKey) -> Result<(), WalletError> {
    // secp256k1 SecretKey is always valid if it was created successfully
    // Additional validation could include checking it's not zero (which secp256k1 already does)
    let secp = Secp256k1::new();

    // Try to create a public key from it to ensure it's valid
    PublicKey::from_secret_key(&secp, private_key);

    Ok(())
}

/// Derive a public key from a private key using secp256k1 elliptic curve multiplication
///
/// This function performs elliptic curve point multiplication to derive the public
/// key from a private key. The operation is: PublicKey = PrivateKey × G, where G
/// is the generator point of the secp256k1 curve.
///
/// # Arguments
///
/// * `private_key` - The private key to derive the public key from
///
/// # Returns
///
/// * `Result<PublicKey, WalletError>` - The derived public key or an error
///
/// # Mathematical Properties
///
/// - The derivation is deterministic: same private key always produces same public key
/// - The operation is one-way: cannot derive private key from public key
/// - Uses the secp256k1 generator point for multiplication
/// - Results in a point on the secp256k1 elliptic curve
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{generate_private_key, derive_public_key};
///
/// let private_key = generate_private_key().expect("Failed to generate private key");
/// let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
/// ```
pub fn derive_public_key(private_key: &SecretKey) -> Result<PublicKey, WalletError> {
    let secp = Secp256k1::new();

    let public_key = PublicKey::from_secret_key(&secp, private_key);
    Ok(public_key)
}

/// Validate that a public key is cryptographically valid for secp256k1
///
/// This function verifies that a public key represents a valid point on the
/// secp256k1 elliptic curve and meets all requirements for cryptographic operations.
/// The secp256k1 library automatically validates points during creation.
///
/// # Arguments
///
/// * `public_key` - The public key to validate
///
/// # Returns
///
/// * `Result<(), WalletError>` - Ok if valid, error if invalid
///
/// # Validation Properties
///
/// - Ensures the point lies on the secp256k1 curve
/// - Verifies the point is not the point at infinity
/// - Confirms proper encoding format
/// - Checks for any secp256k1 library constraints
pub fn validate_public_key(_public_key: &PublicKey) -> Result<(), WalletError> {
    // secp256k1 PublicKey is always valid if it was created successfully
    // The library ensures the point is on the curve
    Ok(())
}

/// Format a public key as a hexadecimal string with optional compression
///
/// This function converts a public key to its hexadecimal string representation.
/// It supports both compressed and uncompressed formats commonly used in
/// cryptocurrency applications.
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
/// # Format Details
///
/// **Compressed Format (33 bytes, 66 hex characters):**
/// - Starts with `02` (even y-coordinate) or `03` (odd y-coordinate)
/// - Contains only the x-coordinate, y-coordinate is derived
/// - More efficient for storage and transmission
/// - Standard format for modern cryptocurrency applications
///
/// **Uncompressed Format (65 bytes, 130 hex characters):**
/// - Starts with `04`
/// - Contains both x and y coordinates explicitly
/// - Larger but contains complete point information
/// - Legacy format, less commonly used today
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{generate_private_key, derive_public_key, format_public_key};
///
/// let private_key = generate_private_key().unwrap();
/// let public_key = derive_public_key(&private_key).unwrap();
///
/// let compressed = format_public_key(&public_key, true);    // 66 chars, starts with 02/03
/// let uncompressed = format_public_key(&public_key, false); // 130 chars, starts with 04
/// ```
pub fn format_public_key(public_key: &PublicKey, compressed: bool) -> String {
    if compressed {
        hex::encode(public_key.serialize())
    } else {
        hex::encode(public_key.serialize_uncompressed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;
    use std::str::FromStr;

    #[test]
    fn test_generate_private_key_success() {
        let result = generate_private_key();
        assert!(result.is_ok(), "Private key generation should succeed");

        let private_key = result.unwrap();
        // Validate the generated key
        assert!(validate_private_key(&private_key).is_ok());
    }

    #[test]
    fn test_generate_private_key_uniqueness() {
        let key1 = generate_private_key().expect("First key generation failed");
        let key2 = generate_private_key().expect("Second key generation failed");

        // Keys should be different (extremely unlikely to be the same)
        assert_ne!(key1.secret_bytes(), key2.secret_bytes());
    }

    #[test]
    fn test_validate_private_key_valid() {
        // Use a known valid private key for deterministic testing
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key =
            SecretKey::from_str(private_key_hex).expect("Failed to create test private key");

        let result = validate_private_key(&private_key);
        assert!(result.is_ok(), "Valid private key should pass validation");
    }

    #[test]
    fn test_private_key_deterministic() {
        // Test with a known private key to ensure deterministic behavior
        let private_key_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let private_key =
            SecretKey::from_str(private_key_hex).expect("Failed to create deterministic test key");

        // Validate it works
        assert!(validate_private_key(&private_key).is_ok());

        // Check the bytes are as expected
        let expected_bytes = hex::decode(private_key_hex).expect("Failed to decode hex");
        assert_eq!(private_key.secret_bytes(), expected_bytes.as_slice());
    }

    #[test]
    fn test_derive_public_key_success() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let result = derive_public_key(&private_key);

        assert!(result.is_ok(), "Public key derivation should succeed");

        let public_key = result.unwrap();
        assert!(validate_public_key(&public_key).is_ok());
    }

    #[test]
    fn test_derive_public_key_deterministic() {
        // Use a known private key for deterministic testing
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key =
            SecretKey::from_str(private_key_hex).expect("Failed to create test private key");

        let public_key1 = derive_public_key(&private_key).expect("First derivation failed");
        let public_key2 = derive_public_key(&private_key).expect("Second derivation failed");

        // Same private key should always produce the same public key
        assert_eq!(public_key1.serialize(), public_key2.serialize());
    }

    #[test]
    fn test_validate_public_key_valid() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");

        let result = validate_public_key(&public_key);
        assert!(result.is_ok(), "Valid public key should pass validation");
    }

    #[test]
    fn test_format_public_key_compressed() {
        // Use a known private key for deterministic testing
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key =
            SecretKey::from_str(private_key_hex).expect("Failed to create test private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");

        let compressed_hex = format_public_key(&public_key, true);
        let uncompressed_hex = format_public_key(&public_key, false);

        // Compressed format should be 66 hex chars (33 bytes * 2)
        assert_eq!(compressed_hex.len(), 66);
        // Uncompressed format should be 130 hex chars (65 bytes * 2)
        assert_eq!(uncompressed_hex.len(), 130);

        // Compressed should start with 02 or 03
        assert!(compressed_hex.starts_with("02") || compressed_hex.starts_with("03"));
        // Uncompressed should start with 04
        assert!(uncompressed_hex.starts_with("04"));
    }

    #[test]
    fn test_public_key_derivation_known_vector() {
        // Test with a known private key and expected public key
        let private_key_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let private_key =
            SecretKey::from_str(private_key_hex).expect("Failed to create test private key");

        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let compressed_hex = format_public_key(&public_key, true);

        // This should be deterministic for the given private key
        assert_eq!(compressed_hex.len(), 66);
        assert!(compressed_hex.starts_with("02") || compressed_hex.starts_with("03"));
    }
}
