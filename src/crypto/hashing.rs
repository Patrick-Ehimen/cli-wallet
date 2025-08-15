use crate::error::WalletError;
use sha2::{Digest, Sha256};

/// Hash a message using SHA-256
///
/// This function takes an arbitrary message and returns its SHA-256 hash.
/// This is commonly used for creating message digests before signing.
///
/// # Arguments
///
/// * `message` - The message bytes to hash
///
/// # Returns
///
/// * `Result<[u8; 32], WalletError>` - The 32-byte SHA-256 hash or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::hash_message;
///
/// let message = b"Hello, world!";
/// let hash = hash_message(message).expect("Failed to hash message");
/// ```
pub fn hash_message(message: &[u8]) -> Result<[u8; 32], WalletError> {
    // Validate input
    if message.is_empty() {
        return Err(WalletError::InvalidInput(
            "Message cannot be empty".to_string(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();

    // Convert to fixed-size array
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);

    Ok(hash)
}

/// Hash a string message using SHA-256
///
/// Convenience function for hashing string messages.
///
/// # Arguments
///
/// * `message` - The string message to hash
///
/// # Returns
///
/// * `Result<[u8; 32], WalletError>` - The 32-byte SHA-256 hash or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::crypto::hash_string_message;
///
/// let hash = hash_string_message("Hello, world!").expect("Failed to hash message");
/// ```
pub fn hash_string_message(message: &str) -> Result<[u8; 32], WalletError> {
    hash_message(message.as_bytes())
}

/// Validate message input before hashing
///
/// # Arguments
///
/// * `message` - The message bytes to validate
///
/// # Returns
///
/// * `Result<(), WalletError>` - Ok if valid, error if invalid
pub fn validate_message_input(message: &[u8]) -> Result<(), WalletError> {
    if message.is_empty() {
        return Err(WalletError::InvalidInput(
            "Message cannot be empty".to_string(),
        ));
    }

    // Additional validation could include maximum message size limits
    const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB limit
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(WalletError::InvalidInput(format!(
            "Message too large: {} bytes (max: {} bytes)",
            message.len(),
            MAX_MESSAGE_SIZE
        )));
    }

    Ok(())
}

/// Convert a hash to a hex string
///
/// # Arguments
///
/// * `hash` - The 32-byte hash to convert
///
/// # Returns
///
/// * `String` - The hex-encoded hash
pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_message_success() {
        let message = b"Hello, world!";
        let result = hash_message(message);

        assert!(result.is_ok(), "Message hashing should succeed");

        let hash = result.unwrap();
        assert_eq!(hash.len(), 32, "SHA-256 hash should be 32 bytes");
    }

    #[test]
    fn test_hash_message_deterministic() {
        let message = b"Test message";

        let hash1 = hash_message(message).expect("First hash failed");
        let hash2 = hash_message(message).expect("Second hash failed");

        assert_eq!(hash1, hash2, "Same message should produce same hash");
    }

    #[test]
    fn test_hash_message_known_vector() {
        // Test with known SHA-256 test vector
        let message = b"abc";
        let expected_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        let hash = hash_message(message).expect("Hash failed");
        let hash_hex = hash_to_hex(&hash);

        assert_eq!(
            hash_hex, expected_hex,
            "Hash should match known test vector"
        );
    }

    #[test]
    fn test_hash_string_message() {
        let message = "Hello, world!";
        let result = hash_string_message(message);

        assert!(result.is_ok(), "String message hashing should succeed");

        // Should produce same result as byte array version
        let byte_hash = hash_message(message.as_bytes()).expect("Byte hash failed");
        let string_hash = result.unwrap();

        assert_eq!(
            byte_hash, string_hash,
            "String and byte hashing should match"
        );
    }

    #[test]
    fn test_hash_message_empty_input() {
        let message = b"";
        let result = hash_message(message);

        assert!(result.is_err(), "Empty message should return error");

        if let Err(WalletError::InvalidInput(msg)) = result {
            assert!(msg.contains("empty"), "Error should mention empty message");
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_validate_message_input_valid() {
        let message = b"Valid message";
        let result = validate_message_input(message);

        assert!(result.is_ok(), "Valid message should pass validation");
    }

    #[test]
    fn test_validate_message_input_empty() {
        let message = b"";
        let result = validate_message_input(message);

        assert!(result.is_err(), "Empty message should fail validation");
    }

    #[test]
    fn test_validate_message_input_too_large() {
        // Create a message larger than the limit
        let large_message = vec![0u8; 1024 * 1024 + 1]; // 1MB + 1 byte
        let result = validate_message_input(&large_message);

        assert!(result.is_err(), "Too large message should fail validation");

        if let Err(WalletError::InvalidInput(msg)) = result {
            assert!(msg.contains("too large"), "Error should mention size limit");
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_hash_to_hex() {
        let hash = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
        ];

        let hex_string = hash_to_hex(&hash);
        let expected = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";

        assert_eq!(
            hex_string, expected,
            "Hash to hex conversion should be correct"
        );
        assert_eq!(hex_string.len(), 64, "Hex string should be 64 characters");
    }

    #[test]
    fn test_different_messages_different_hashes() {
        let message1 = b"Message 1";
        let message2 = b"Message 2";

        let hash1 = hash_message(message1).expect("First hash failed");
        let hash2 = hash_message(message2).expect("Second hash failed");

        assert_ne!(
            hash1, hash2,
            "Different messages should produce different hashes"
        );
    }
}
