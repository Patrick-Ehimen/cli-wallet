use crate::crypto::hash_message;
use crate::error::WalletError;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};

/// Sign a message using secp256k1 ECDSA
///
/// This function takes a message and private key, hashes the message using SHA-256,
/// and creates a digital signature using the secp256k1 elliptic curve algorithm.
///
/// # Arguments
///
/// * `message` - The message bytes to sign
/// * `private_key` - The private key to use for signing
///
/// # Returns
///
/// * `Result<Signature, WalletError>` - The signature or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{sign_message, generate_private_key};
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let message = b"Hello, world!";
/// let signature = sign_message(message, &private_key).expect("Failed to sign message");
/// ```
pub fn sign_message(message: &[u8], private_key: &SecretKey) -> Result<Signature, WalletError> {
    // Validate inputs
    if message.is_empty() {
        return Err(WalletError::signing("Message cannot be empty"));
    }

    // Hash the message using SHA-256
    let message_hash = hash_message(message)
        .map_err(|e| WalletError::signing(format!("Failed to hash message: {}", e)))?;

    // Create secp256k1 context
    let secp = Secp256k1::new();

    // Convert hash to Message for signing
    let message_obj = Message::from_digest(message_hash);

    // Sign the message
    let signature = secp.sign_ecdsa(&message_obj, private_key);

    Ok(signature)
}

/// Sign a string message using secp256k1 ECDSA
///
/// Convenience function for signing string messages.
///
/// # Arguments
///
/// * `message` - The string message to sign
/// * `private_key` - The private key to use for signing
///
/// # Returns
///
/// * `Result<Signature, WalletError>` - The signature or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{sign_string_message, generate_private_key};
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let signature = sign_string_message("Hello, world!", &private_key).expect("Failed to sign");
/// ```
pub fn sign_string_message(
    message: &str,
    private_key: &SecretKey,
) -> Result<Signature, WalletError> {
    sign_message(message.as_bytes(), private_key)
}

/// Format a signature as a hex string
///
/// This function converts a secp256k1 signature to a hex-encoded string
/// for display or storage purposes.
///
/// # Arguments
///
/// * `signature` - The signature to format
///
/// # Returns
///
/// * `String` - The signature encoded as a hex string (128 characters)
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{sign_message, format_signature, generate_private_key};
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let message = b"Hello, world!";
/// let signature = sign_message(message, &private_key).expect("Failed to sign");
/// let signature_hex = format_signature(&signature);
/// ```
pub fn format_signature(signature: &Signature) -> String {
    hex::encode(signature.serialize_compact())
}

/// Parse a signature from a hex string
///
/// This function converts a hex-encoded signature string back to a secp256k1 Signature.
///
/// # Arguments
///
/// * `hex_str` - The hex string to parse (should be 128 characters)
///
/// # Returns
///
/// * `Result<Signature, WalletError>` - The parsed signature or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{sign_message, format_signature, parse_signature_hex, generate_private_key};
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let message = b"Hello, world!";
/// let signature = sign_message(message, &private_key).expect("Failed to sign");
/// let signature_hex = format_signature(&signature);
/// let parsed_signature = parse_signature_hex(&signature_hex).expect("Failed to parse");
/// ```
pub fn parse_signature_hex(hex_str: &str) -> Result<Signature, WalletError> {
    // Check length (128 hex characters = 64 bytes)
    if hex_str.len() != 128 {
        return Err(WalletError::invalid_input(format!(
            "Signature hex string must be 128 characters, got {}",
            hex_str.len()
        )));
    }

    // Decode hex string to bytes
    let bytes = hex::decode(hex_str)
        .map_err(|e| WalletError::invalid_input(format!("Invalid hex format: {}", e)))?;

    // Create Signature from bytes
    Signature::from_compact(&bytes)
        .map_err(|e| WalletError::invalid_input(format!("Invalid signature format: {}", e)))
}

/// Validate signature input parameters
///
/// This function validates that all parameters required for signature verification
/// are in the correct format and within acceptable ranges.
///
/// # Arguments
///
/// * `message` - The message bytes to validate
/// * `signature` - The signature to validate
/// * `public_key` - The public key to validate
///
/// # Returns
///
/// * `Result<(), WalletError>` - Ok if all parameters are valid, error otherwise
pub fn validate_signature_params(
    message: &[u8],
    _signature: &Signature,
    _public_key: &PublicKey,
) -> Result<(), WalletError> {
    // Validate message
    if message.is_empty() {
        return Err(WalletError::invalid_input("Message cannot be empty"));
    }

    // Additional validation could include maximum message size limits
    const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB limit
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(WalletError::invalid_input(format!(
            "Message too large: {} bytes (max: {} bytes)",
            message.len(),
            MAX_MESSAGE_SIZE
        )));
    }

    // Signature and public key validation is handled by secp256k1 library
    // during verification, so we don't need additional checks here

    Ok(())
}

/// Verify a message signature using secp256k1 ECDSA
///
/// This function verifies that a signature was created by the holder of the
/// private key corresponding to the given public key for the given message.
///
/// # Arguments
///
/// * `message` - The original message bytes that were signed
/// * `signature` - The signature to verify
/// * `public_key` - The public key to verify against
///
/// # Returns
///
/// * `Result<bool, WalletError>` - True if signature is valid, false if invalid, error on failure
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::{sign_message, verify_signature, generate_private_key, derive_public_key};
///
/// let private_key = generate_private_key().expect("Failed to generate key");
/// let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
/// let message = b"Hello, world!";
/// let signature = sign_message(message, &private_key).expect("Failed to sign");
/// let is_valid = verify_signature(message, &signature, &public_key).expect("Failed to verify");
/// assert!(is_valid);
/// ```
pub fn verify_signature(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<bool, WalletError> {
    // Validate inputs
    validate_signature_params(message, signature, public_key)?;

    // Hash the message using SHA-256
    let message_hash = hash_message(message)
        .map_err(|e| WalletError::verification(format!("Failed to hash message: {}", e)))?;

    // Create secp256k1 context
    let secp = Secp256k1::new();

    // Convert hash to Message for verification
    let message_obj = Message::from_digest(message_hash);

    // Verify the signature
    match secp.verify_ecdsa(&message_obj, signature, public_key) {
        Ok(()) => Ok(true),
        Err(secp256k1::Error::IncorrectSignature) => Ok(false),
        Err(e) => Err(WalletError::verification(format!(
            "Signature verification failed: {}",
            e
        ))),
    }
}

/// Verify a string message signature
///
/// Convenience function for verifying signatures on string messages.
///
/// # Arguments
///
/// * `message` - The original string message that was signed
/// * `signature` - The signature to verify
/// * `public_key` - The public key to verify against
///
/// # Returns
///
/// * `Result<bool, WalletError>` - True if signature is valid, false if invalid, error on failure
pub fn verify_string_signature(
    message: &str,
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<bool, WalletError> {
    verify_signature(message.as_bytes(), signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_public_key, generate_private_key};
    use std::str::FromStr;

    #[test]
    fn test_sign_message_success() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = b"Hello, world!";

        let result = sign_message(message, &private_key);
        assert!(result.is_ok(), "Message signing should succeed");

        let signature = result.unwrap();
        // Signature should be valid secp256k1 signature (64 bytes when serialized)
        assert_eq!(signature.serialize_compact().len(), 64);
    }

    #[test]
    fn test_sign_string_message() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = "Hello, world!";

        let result = sign_string_message(message, &private_key);
        assert!(result.is_ok(), "String message signing should succeed");

        // Should produce same result as byte array version
        let byte_signature =
            sign_message(message.as_bytes(), &private_key).expect("Byte message signing failed");
        let string_signature = result.unwrap();

        assert_eq!(
            byte_signature.serialize_compact(),
            string_signature.serialize_compact(),
            "String and byte signing should produce same result"
        );
    }

    #[test]
    fn test_sign_message_empty_input() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = b"";

        let result = sign_message(message, &private_key);
        assert!(result.is_err(), "Empty message should return error");

        if let Err(WalletError::SigningError(msg)) = result {
            assert!(msg.contains("empty"), "Error should mention empty message");
        } else {
            panic!("Expected SigningError");
        }
    }

    #[test]
    fn test_format_signature() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = b"Test message";
        let signature = sign_message(message, &private_key).expect("Failed to sign message");

        let formatted = format_signature(&signature);

        // Should be 128 hex characters (64 bytes * 2)
        assert_eq!(
            formatted.len(),
            128,
            "Formatted signature should be 128 characters"
        );

        // Should be valid hex
        assert!(
            hex::decode(&formatted).is_ok(),
            "Formatted signature should be valid hex"
        );

        // Should be deterministic
        let formatted2 = format_signature(&signature);
        assert_eq!(formatted, formatted2, "Formatting should be deterministic");
    }

    #[test]
    fn test_parse_signature_hex_valid() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = b"Test message";
        let original_signature =
            sign_message(message, &private_key).expect("Failed to sign message");
        let signature_hex = format_signature(&original_signature);

        let result = parse_signature_hex(&signature_hex);
        assert!(
            result.is_ok(),
            "Valid signature hex should parse successfully"
        );

        let parsed_signature = result.unwrap();
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
        assert!(result.is_err(), "Short signature hex should fail");

        let long_hex = "1234567890abcdef".repeat(10);
        let result = parse_signature_hex(&long_hex);
        assert!(result.is_err(), "Long signature hex should fail");
    }

    #[test]
    fn test_parse_signature_hex_invalid_hex() {
        let invalid_hex = "g".repeat(128);
        let result = parse_signature_hex(&invalid_hex);
        assert!(result.is_err(), "Invalid hex characters should fail");
    }

    #[test]
    fn test_verify_signature_valid() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let message = b"Test message for verification";

        let signature = sign_message(message, &private_key).expect("Failed to sign message");
        let result = verify_signature(message, &signature, &public_key);

        assert!(result.is_ok(), "Signature verification should succeed");
        assert!(result.unwrap(), "Valid signature should verify as true");
    }

    #[test]
    fn test_verify_signature_invalid() {
        let private_key1 = generate_private_key().expect("Failed to generate first private key");
        let private_key2 = generate_private_key().expect("Failed to generate second private key");
        let public_key2 = derive_public_key(&private_key2).expect("Failed to derive public key");
        let message = b"Test message for verification";

        // Sign with key1 but verify with key2's public key
        let signature = sign_message(message, &private_key1).expect("Failed to sign message");
        let result = verify_signature(message, &signature, &public_key2);

        assert!(result.is_ok(), "Verification should complete without error");
        assert!(!result.unwrap(), "Invalid signature should verify as false");
    }

    #[test]
    fn test_verify_signature_wrong_message() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let original_message = b"Original message";
        let different_message = b"Different message";

        let signature =
            sign_message(original_message, &private_key).expect("Failed to sign message");
        let result = verify_signature(different_message, &signature, &public_key);

        assert!(result.is_ok(), "Verification should complete without error");
        assert!(
            !result.unwrap(),
            "Signature for different message should verify as false"
        );
    }

    #[test]
    fn test_verify_string_signature() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let message = "Test string message";

        let signature = sign_string_message(message, &private_key).expect("Failed to sign message");
        let result = verify_string_signature(message, &signature, &public_key);

        assert!(
            result.is_ok(),
            "String signature verification should succeed"
        );
        assert!(
            result.unwrap(),
            "Valid string signature should verify as true"
        );
    }

    #[test]
    fn test_validate_signature_params_valid() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let message = b"Valid message";
        let signature = sign_message(message, &private_key).expect("Failed to sign message");

        let result = validate_signature_params(message, &signature, &public_key);
        assert!(result.is_ok(), "Valid parameters should pass validation");
    }

    #[test]
    fn test_validate_signature_params_empty_message() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let message = b"";
        let signature = sign_message(b"dummy", &private_key).expect("Failed to sign dummy message");

        let result = validate_signature_params(message, &signature, &public_key);
        assert!(result.is_err(), "Empty message should fail validation");
    }

    #[test]
    fn test_validate_signature_params_large_message() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let large_message = vec![0u8; 1024 * 1024 + 1]; // 1MB + 1 byte
        let signature = sign_message(b"dummy", &private_key).expect("Failed to sign dummy message");

        let result = validate_signature_params(&large_message, &signature, &public_key);
        assert!(result.is_err(), "Too large message should fail validation");
    }

    #[test]
    fn test_sign_verify_round_trip() {
        // Test complete sign -> verify workflow
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let message = b"Round trip test message";

        // Sign the message
        let signature = sign_message(message, &private_key).expect("Failed to sign message");

        // Verify the signature
        let is_valid =
            verify_signature(message, &signature, &public_key).expect("Failed to verify signature");

        assert!(is_valid, "Round trip signature should be valid");
    }

    #[test]
    fn test_signature_deterministic() {
        // Test that same message and key produce same signature
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key = SecretKey::from_str(private_key_hex).expect("Failed to create test key");
        let message = b"Deterministic test message";

        let signature1 = sign_message(message, &private_key).expect("First signature failed");
        let signature2 = sign_message(message, &private_key).expect("Second signature failed");

        assert_eq!(
            signature1.serialize_compact(),
            signature2.serialize_compact(),
            "Same message and key should produce same signature"
        );
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message1 = b"First message";
        let message2 = b"Second message";

        let signature1 = sign_message(message1, &private_key).expect("First signature failed");
        let signature2 = sign_message(message2, &private_key).expect("Second signature failed");

        assert_ne!(
            signature1.serialize_compact(),
            signature2.serialize_compact(),
            "Different messages should produce different signatures"
        );
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let private_key1 = generate_private_key().expect("Failed to generate first private key");
        let private_key2 = generate_private_key().expect("Failed to generate second private key");
        let message = b"Same message";

        let signature1 = sign_message(message, &private_key1).expect("First signature failed");
        let signature2 = sign_message(message, &private_key2).expect("Second signature failed");

        // Different keys should produce different signatures (extremely unlikely to be same)
        assert_ne!(
            signature1.serialize_compact(),
            signature2.serialize_compact(),
            "Different keys should produce different signatures"
        );
    }

    #[test]
    fn test_signature_format_parse_round_trip() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let message = b"Format parse test";
        let original_signature =
            sign_message(message, &private_key).expect("Failed to sign message");

        // Format to hex
        let signature_hex = format_signature(&original_signature);

        // Parse back from hex
        let parsed_signature =
            parse_signature_hex(&signature_hex).expect("Failed to parse signature hex");

        assert_eq!(
            original_signature.serialize_compact(),
            parsed_signature.serialize_compact(),
            "Format -> parse round trip should preserve signature"
        );
    }

    #[test]
    fn test_error_handling_invalid_private_key() {
        // Test with zero private key (invalid for secp256k1)
        let zero_key_bytes = [0u8; 32];
        let result = SecretKey::from_slice(&zero_key_bytes);
        assert!(result.is_err(), "Zero private key should be invalid");
    }

    #[test]
    fn test_signature_verification_error_handling() {
        let private_key = generate_private_key().expect("Failed to generate private key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let message = b"";

        // This should fail during validation, not verification
        let signature = sign_message(b"dummy", &private_key).expect("Failed to sign dummy");
        let result = verify_signature(message, &signature, &public_key);

        assert!(
            result.is_err(),
            "Empty message should cause validation error"
        );
        assert!(matches!(result.unwrap_err(), WalletError::InvalidInput(_)));
    }

    #[test]
    fn test_known_signature_vector() {
        // Test with a known private key and message for reproducible results
        let private_key_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let private_key = SecretKey::from_str(private_key_hex).expect("Failed to create test key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
        let message = b"test message";

        let signature = sign_message(message, &private_key).expect("Failed to sign message");
        let is_valid =
            verify_signature(message, &signature, &public_key).expect("Failed to verify signature");

        assert!(is_valid, "Known vector signature should be valid");

        // Test that signature is deterministic for this key/message combination
        let signature2 = sign_message(message, &private_key).expect("Failed to sign message again");
        assert_eq!(
            signature.serialize_compact(),
            signature2.serialize_compact(),
            "Signature should be deterministic"
        );
    }
}
