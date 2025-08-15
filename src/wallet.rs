use crate::crypto::{
    derive_public_key, format_public_key, format_signature, generate_private_key, hash_message,
    parse_signature_hex, sign_message, verify_signature,
};
use crate::error::WalletError;
use secp256k1::{PublicKey, SecretKey};
use std::fmt;

/// Wallet struct containing a secp256k1 key pair
///
/// This struct represents a cryptocurrency wallet with a private key for signing
/// and a corresponding public key for verification and address generation.
#[derive(Debug, Clone)]
pub struct Wallet {
    private_key: SecretKey,
    public_key: PublicKey,
}

impl Wallet {
    /// Create a new wallet with a randomly generated key pair
    ///
    /// This method generates a new secure random private key and derives
    /// the corresponding public key using secp256k1 elliptic curve cryptography.
    ///
    /// # Returns
    ///
    /// * `Result<Wallet, WalletError>` - A new wallet instance or an error
    ///
    /// # Examples
    ///
    /// ```
    /// use cli_wallet::wallet::Wallet;
    ///
    /// let wallet = Wallet::new().expect("Failed to create wallet");
    /// ```
    pub fn new() -> Result<Wallet, WalletError> {
        // Generate a new private key using the crypto module
        let private_key = generate_private_key().map_err(|e| {
            WalletError::key_generation(format!("Failed to generate private key: {}", e))
        })?;

        // Derive the corresponding public key
        let public_key = derive_public_key(&private_key).map_err(|e| {
            WalletError::key_generation(format!("Failed to derive public key: {}", e))
        })?;

        Ok(Wallet {
            private_key,
            public_key,
        })
    }

    /// Generate and return formatted key pair strings
    ///
    /// This method returns both the private and public keys as hex-encoded strings
    /// suitable for display or storage. The public key is returned in compressed format.
    ///
    /// # Returns
    ///
    /// * `Result<(String, String), WalletError>` - Tuple of (private_key_hex, public_key_hex)
    ///
    /// # Examples
    ///
    /// ```
    /// use cli_wallet::wallet::Wallet;
    ///
    /// let wallet = Wallet::new().expect("Failed to create wallet");
    /// let (private_hex, public_hex) = wallet.generate_keypair().expect("Failed to format keys");
    /// ```
    pub fn generate_keypair(&self) -> Result<(String, String), WalletError> {
        let private_key_hex = self.get_private_key_hex();
        let public_key_hex = self.get_public_key_hex();

        Ok((private_key_hex, public_key_hex))
    }

    /// Get the private key as a hex string
    ///
    /// # Returns
    ///
    /// * `String` - The private key encoded as a 64-character hex string
    pub fn get_private_key_hex(&self) -> String {
        format_private_key(&self.private_key)
    }

    /// Get the public key as a hex string
    ///
    /// # Returns
    ///
    /// * `String` - The public key encoded as a 66-character hex string (compressed format)
    pub fn get_public_key_hex(&self) -> String {
        format_public_key(&self.public_key, true) // Use compressed format
    }

    /// Get a reference to the private key
    ///
    /// # Returns
    ///
    /// * `&SecretKey` - Reference to the internal private key
    pub fn get_private_key(&self) -> &SecretKey {
        &self.private_key
    }

    /// Get a reference to the public key
    ///
    /// # Returns
    ///
    /// * `&PublicKey` - Reference to the internal public key
    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Generate a wallet address from the public key
    ///
    /// This method creates a wallet address by hashing the public key using SHA-256
    /// and then formatting it as a hex string. The address serves as a unique
    /// identifier for the wallet that can be shared publicly.
    ///
    /// # Returns
    ///
    /// * `Result<String, WalletError>` - The wallet address as a hex string or an error
    ///
    /// # Examples
    ///
    /// ```
    /// use cli_wallet::wallet::Wallet;
    ///
    /// let wallet = Wallet::new().expect("Failed to create wallet");
    /// let address = wallet.create_address().expect("Failed to create address");
    /// ```
    pub fn create_address(&self) -> Result<String, WalletError> {
        generate_address_from_public_key(&self.public_key)
    }

    /// Sign a message using the wallet's private key
    ///
    /// This method signs a message using the wallet's private key and the secp256k1
    /// ECDSA algorithm. The message is first hashed using SHA-256 before signing.
    ///
    /// # Arguments
    ///
    /// * `message` - The message bytes to sign
    ///
    /// # Returns
    ///
    /// * `Result<String, WalletError>` - The signature as a hex string or an error
    ///
    /// # Examples
    ///
    /// ```
    /// use cli_wallet::wallet::Wallet;
    ///
    /// let wallet = Wallet::new().expect("Failed to create wallet");
    /// let message = b"Hello, world!";
    /// let signature = wallet.sign_message(message).expect("Failed to sign message");
    /// ```
    pub fn sign_message(&self, message: &[u8]) -> Result<String, WalletError> {
        let signature = sign_message(message, &self.private_key)?;
        Ok(format_signature(&signature))
    }

    /// Sign a string message using the wallet's private key
    ///
    /// Convenience method for signing string messages.
    ///
    /// # Arguments
    ///
    /// * `message` - The string message to sign
    ///
    /// # Returns
    ///
    /// * `Result<String, WalletError>` - The signature as a hex string or an error
    ///
    /// # Examples
    ///
    /// ```
    /// use cli_wallet::wallet::Wallet;
    ///
    /// let wallet = Wallet::new().expect("Failed to create wallet");
    /// let signature = wallet.sign_string_message("Hello, world!").expect("Failed to sign");
    /// ```
    pub fn sign_string_message(&self, message: &str) -> Result<String, WalletError> {
        self.sign_message(message.as_bytes())
    }

    /// Verify a message signature using the wallet's public key
    ///
    /// This method verifies that a signature was created by the holder of the
    /// private key corresponding to this wallet's public key for the given message.
    /// The signature should be provided as a hex-encoded string.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message bytes that were signed
    /// * `signature_hex` - The signature as a hex string (128 characters)
    ///
    /// # Returns
    ///
    /// * `Result<bool, WalletError>` - True if signature is valid, false if invalid, error on failure
    ///
    /// # Examples
    ///
    /// ```
    /// use cli_wallet::wallet::Wallet;
    ///
    /// let wallet = Wallet::new().expect("Failed to create wallet");
    /// let message = b"Hello, world!";
    /// let signature = wallet.sign_message(message).expect("Failed to sign message");
    /// let is_valid = wallet.verify_signature(message, &signature).expect("Failed to verify");
    /// assert!(is_valid);
    /// ```
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature_hex: &str,
    ) -> Result<bool, WalletError> {
        // Parse the signature from hex string
        let signature = parse_signature_hex(signature_hex)?;

        // Verify the signature using the wallet's public key
        verify_signature(message, &signature, &self.public_key)
    }

    /// Verify a string message signature using the wallet's public key
    ///
    /// Convenience method for verifying signatures on string messages.
    ///
    /// # Arguments
    ///
    /// * `message` - The original string message that was signed
    /// * `signature_hex` - The signature as a hex string (128 characters)
    ///
    /// # Returns
    ///
    /// * `Result<bool, WalletError>` - True if signature is valid, false if invalid, error on failure
    ///
    /// # Examples
    ///
    /// ```
    /// use cli_wallet::wallet::Wallet;
    ///
    /// let wallet = Wallet::new().expect("Failed to create wallet");
    /// let signature = wallet.sign_string_message("Hello, world!").expect("Failed to sign");
    /// let is_valid = wallet.verify_string_signature("Hello, world!", &signature).expect("Failed to verify");
    /// assert!(is_valid);
    /// ```
    pub fn verify_string_signature(
        &self,
        message: &str,
        signature_hex: &str,
    ) -> Result<bool, WalletError> {
        self.verify_signature(message.as_bytes(), signature_hex)
    }
}

/// Display implementation for user-friendly wallet output
impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Private Key: {}\nPublic Key: {}",
            self.get_private_key_hex(),
            self.get_public_key_hex()
        )
    }
}

/// Format a private key as a hex string
///
/// # Arguments
///
/// * `key` - The private key to format
///
/// # Returns
///
/// * `String` - The private key as a 64-character hex string
pub fn format_private_key(key: &SecretKey) -> String {
    hex::encode(key.secret_bytes())
}

/// Validate and parse a private key from a hex string
///
/// # Arguments
///
/// * `hex_str` - The hex string to parse (should be 64 characters)
///
/// # Returns
///
/// * `Result<SecretKey, WalletError>` - The parsed private key or an error
pub fn validate_private_key_hex(hex_str: &str) -> Result<SecretKey, WalletError> {
    // Check length (64 hex characters = 32 bytes)
    if hex_str.len() != 64 {
        return Err(WalletError::invalid_input(format!(
            "Private key hex string must be 64 characters, got {}",
            hex_str.len()
        )));
    }

    // Decode hex string to bytes
    let bytes = hex::decode(hex_str)
        .map_err(|e| WalletError::invalid_input(format!("Invalid hex format: {}", e)))?;

    // Create SecretKey from bytes
    SecretKey::from_slice(&bytes)
        .map_err(|e| WalletError::key_generation(format!("Invalid private key: {}", e)))
}

/// Validate and parse a public key from a hex string
///
/// # Arguments
///
/// * `hex_str` - The hex string to parse (66 chars for compressed, 130 for uncompressed)
///
/// # Returns
///
/// * `Result<PublicKey, WalletError>` - The parsed public key or an error
pub fn validate_public_key_hex(hex_str: &str) -> Result<PublicKey, WalletError> {
    // Check length (66 for compressed, 130 for uncompressed)
    if hex_str.len() != 66 && hex_str.len() != 130 {
        return Err(WalletError::invalid_input(format!(
            "Public key hex string must be 66 (compressed) or 130 (uncompressed) characters, got {}",
            hex_str.len()
        )));
    }

    // Decode hex string to bytes
    let bytes = hex::decode(hex_str)
        .map_err(|e| WalletError::invalid_input(format!("Invalid hex format: {}", e)))?;

    // Create PublicKey from bytes
    PublicKey::from_slice(&bytes)
        .map_err(|e| WalletError::invalid_input(format!("Invalid public key: {}", e)))
}

/// Generate a wallet address from a public key using SHA-256
///
/// This function creates a wallet address by taking the SHA-256 hash of the
/// compressed public key and encoding it as a hex string. This follows a
/// simplified address generation scheme suitable for educational purposes.
///
/// # Arguments
///
/// * `public_key` - The public key to generate an address from
///
/// # Returns
///
/// * `Result<String, WalletError>` - The wallet address as a hex string or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::wallet::generate_address_from_public_key;
/// use cli_wallet::crypto::generate_private_key;
/// use cli_wallet::crypto::derive_public_key;
///
/// let private_key = generate_private_key().expect("Failed to generate private key");
/// let public_key = derive_public_key(&private_key).expect("Failed to derive public key");
/// let address = generate_address_from_public_key(&public_key).expect("Failed to generate address");
/// ```
pub fn generate_address_from_public_key(public_key: &PublicKey) -> Result<String, WalletError> {
    // Get the compressed public key bytes (33 bytes)
    let public_key_bytes = public_key.serialize();

    // Hash the public key using SHA-256
    let address_hash = hash_message(&public_key_bytes)
        .map_err(|e| WalletError::address(format!("Failed to hash public key: {}", e)))?;

    // Take the first 20 bytes of the hash (similar to Bitcoin/Ethereum)
    let address_bytes = &address_hash[..20];

    // Encode as hex string
    let address = hex::encode(address_bytes);

    Ok(address)
}

/// Validate a wallet address format
///
/// This function checks if a given string is a valid wallet address format.
/// A valid address should be a 40-character hex string (20 bytes encoded as hex).
///
/// # Arguments
///
/// * `address` - The address string to validate
///
/// # Returns
///
/// * `Result<(), WalletError>` - Ok if valid, error if invalid
///
/// # Examples
///
/// ```
/// use cli_wallet::wallet::validate_address_format;
///
/// let valid_address = "1234567890abcdef1234567890abcdef12345678";
/// assert!(validate_address_format(valid_address).is_ok());
/// ```
pub fn validate_address_format(address: &str) -> Result<(), WalletError> {
    // Check length (40 hex characters = 20 bytes)
    if address.len() != 40 {
        return Err(WalletError::address(format!(
            "Address must be 40 hex characters, got {}",
            address.len()
        )));
    }

    // Check if it's valid hex
    hex::decode(address)
        .map_err(|e| WalletError::address(format!("Invalid address hex format: {}", e)))?;

    Ok(())
}

/// Format an address for display with optional prefix
///
/// This function formats a wallet address for user-friendly display,
/// optionally adding a prefix to indicate the address type.
///
/// # Arguments
///
/// * `address` - The address to format
/// * `with_prefix` - Whether to add a "0x" prefix
///
/// # Returns
///
/// * `String` - The formatted address
///
/// # Examples
///
/// ```
/// use cli_wallet::wallet::format_address;
///
/// let address = "1234567890abcdef1234567890abcdef12345678";
/// let formatted = format_address(address, true);
/// assert_eq!(formatted, "0x1234567890abcdef1234567890abcdef12345678");
/// ```
pub fn format_address(address: &str, with_prefix: bool) -> String {
    if with_prefix {
        format!("0x{}", address)
    } else {
        address.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_wallet_creation() {
        // Test successful wallet creation
        let wallet = Wallet::new();
        assert!(wallet.is_ok(), "Wallet creation should succeed");

        let wallet = wallet.unwrap();

        // Verify that keys are valid by checking they can be used
        let private_key = wallet.get_private_key();
        let public_key = wallet.get_public_key();

        // Verify the public key was derived from the private key
        let derived_public = derive_public_key(private_key).expect("Should derive public key");
        assert_eq!(public_key.serialize(), derived_public.serialize());
    }

    #[test]
    fn test_generate_keypair() {
        // Test key pair generation and formatting
        let wallet = Wallet::new().expect("Failed to create wallet");
        let result = wallet.generate_keypair();

        assert!(result.is_ok(), "Key pair generation should succeed");

        let (private_hex, public_hex) = result.unwrap();

        // Private key should be 64 hex characters (32 bytes * 2)
        assert_eq!(
            private_hex.len(),
            64,
            "Private key should be 64 hex characters"
        );

        // Public key should be 66 hex characters (33 bytes * 2, compressed format)
        assert_eq!(
            public_hex.len(),
            66,
            "Public key should be 66 hex characters"
        );

        // Both should be valid hex strings
        assert!(
            hex::decode(&private_hex).is_ok(),
            "Private key should be valid hex"
        );
        assert!(
            hex::decode(&public_hex).is_ok(),
            "Public key should be valid hex"
        );

        // Public key should start with 02 or 03 (compressed format)
        assert!(
            public_hex.starts_with("02") || public_hex.starts_with("03"),
            "Compressed public key should start with 02 or 03"
        );
    }

    #[test]
    fn test_key_formatting() {
        // Test individual key formatting methods
        let wallet = Wallet::new().expect("Failed to create wallet");

        let private_hex = wallet.get_private_key_hex();
        let public_hex = wallet.get_public_key_hex();

        // Check formatting consistency
        assert_eq!(private_hex.len(), 64);
        assert_eq!(public_hex.len(), 66);

        // Verify hex strings are valid
        assert!(hex::decode(&private_hex).is_ok());
        assert!(hex::decode(&public_hex).is_ok());

        // Test that multiple calls return the same result
        assert_eq!(private_hex, wallet.get_private_key_hex());
        assert_eq!(public_hex, wallet.get_public_key_hex());
    }

    #[test]
    fn test_display_formatting() {
        // Test Display trait implementation
        let wallet = Wallet::new().expect("Failed to create wallet");
        let output = format!("{}", wallet);

        // Check that output contains expected labels
        assert!(
            output.contains("Private Key:"),
            "Output should contain 'Private Key:'"
        );
        assert!(
            output.contains("Public Key:"),
            "Output should contain 'Public Key:'"
        );

        // Check that output contains the actual key values
        assert!(output.contains(&wallet.get_private_key_hex()));
        assert!(output.contains(&wallet.get_public_key_hex()));

        // Check that output is properly formatted with newline
        assert!(
            output.contains('\n'),
            "Output should contain newline between keys"
        );
    }

    #[test]
    fn test_format_private_key() {
        // Test private key formatting function
        let private_key_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let private_key = SecretKey::from_str(private_key_hex).expect("Failed to create test key");

        let formatted = format_private_key(&private_key);
        assert_eq!(formatted, private_key_hex);
        assert_eq!(formatted.len(), 64);
    }

    #[test]
    fn test_validate_private_key_hex_valid() {
        // Test validation with valid private key
        let valid_private_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result = validate_private_key_hex(valid_private_hex);

        assert!(result.is_ok(), "Valid private key should pass validation");

        let private_key = result.unwrap();
        assert_eq!(hex::encode(private_key.secret_bytes()), valid_private_hex);
    }

    #[test]
    fn test_validate_private_key_hex_invalid_length() {
        // Test validation with invalid length
        let invalid_short = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8";
        let result = validate_private_key_hex(invalid_short);
        assert!(result.is_err(), "Short private key should fail validation");

        let invalid_long = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500";
        let result = validate_private_key_hex(invalid_long);
        assert!(result.is_err(), "Long private key should fail validation");
    }

    #[test]
    fn test_validate_private_key_hex_invalid_hex() {
        // Test validation with invalid hex characters
        let invalid_hex = "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result = validate_private_key_hex(invalid_hex);
        assert!(result.is_err(), "Invalid hex should fail validation");
    }

    #[test]
    fn test_validate_private_key_hex_zero_key() {
        // Test validation with zero key (invalid for secp256k1)
        let zero_key = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = validate_private_key_hex(zero_key);
        assert!(result.is_err(), "Zero private key should fail validation");
    }

    #[test]
    fn test_validate_public_key_hex_compressed() {
        // Test validation with valid compressed public key
        let wallet = Wallet::new().expect("Failed to create wallet");
        let public_hex = wallet.get_public_key_hex();

        let result = validate_public_key_hex(&public_hex);
        assert!(
            result.is_ok(),
            "Valid compressed public key should pass validation"
        );

        let public_key = result.unwrap();
        assert_eq!(format_public_key(&public_key, true), public_hex);
    }

    #[test]
    fn test_validate_public_key_hex_uncompressed() {
        // Test validation with uncompressed public key
        let wallet = Wallet::new().expect("Failed to create wallet");
        let public_key_uncompressed = format_public_key(wallet.get_public_key(), false);

        let result = validate_public_key_hex(&public_key_uncompressed);
        assert!(
            result.is_ok(),
            "Valid uncompressed public key should pass validation"
        );

        assert_eq!(public_key_uncompressed.len(), 130);
        assert!(public_key_uncompressed.starts_with("04"));
    }

    #[test]
    fn test_validate_public_key_hex_invalid_length() {
        // Test validation with invalid length
        let invalid_short = "02e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8";
        let result = validate_public_key_hex(invalid_short);
        assert!(result.is_err(), "Short public key should fail validation");

        let invalid_medium = "02e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500";
        let result = validate_public_key_hex(invalid_medium);
        assert!(
            result.is_err(),
            "Medium length public key should fail validation"
        );
    }

    #[test]
    fn test_validate_public_key_hex_invalid_hex() {
        // Test validation with invalid hex characters
        let invalid_hex = "02g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result = validate_public_key_hex(invalid_hex);
        assert!(result.is_err(), "Invalid hex should fail validation");
    }

    #[test]
    fn test_deterministic_keys() {
        // Test with known test vectors for deterministic behavior
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key = SecretKey::from_str(private_key_hex).expect("Failed to create test key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");

        // Create wallet with these keys (we'd need a constructor for this in a real implementation)
        // For now, just test the formatting functions
        let formatted_private = format_private_key(&private_key);
        let formatted_public = format_public_key(&public_key, true);

        assert_eq!(formatted_private, private_key_hex);
        assert_eq!(formatted_public.len(), 66);

        // Test that the same private key always produces the same public key
        let public_key2 =
            derive_public_key(&private_key).expect("Failed to derive public key again");
        assert_eq!(public_key.serialize(), public_key2.serialize());
    }

    #[test]
    fn test_wallet_uniqueness() {
        // Test that different wallets have different keys
        let wallet1 = Wallet::new().expect("Failed to create first wallet");
        let wallet2 = Wallet::new().expect("Failed to create second wallet");

        // Keys should be different (extremely unlikely to be the same)
        assert_ne!(
            wallet1.get_private_key().secret_bytes(),
            wallet2.get_private_key().secret_bytes()
        );
        assert_ne!(
            wallet1.get_public_key().serialize(),
            wallet2.get_public_key().serialize()
        );
    }

    #[test]
    fn test_key_relationship() {
        // Test that public key is correctly derived from private key
        let wallet = Wallet::new().expect("Failed to create wallet");

        // Derive public key manually and compare
        let derived_public =
            derive_public_key(wallet.get_private_key()).expect("Failed to derive public key");

        assert_eq!(
            wallet.get_public_key().serialize(),
            derived_public.serialize(),
            "Wallet public key should match manually derived public key"
        );
    }

    #[test]
    fn test_error_handling() {
        // Test error cases for validation functions
        let result = validate_private_key_hex("invalid");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WalletError::InvalidInput(_)));

        let result = validate_public_key_hex("invalid");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WalletError::InvalidInput(_)));
    }

    #[test]
    fn test_create_address() {
        // Test address creation from wallet
        let wallet = Wallet::new().expect("Failed to create wallet");
        let result = wallet.create_address();

        assert!(result.is_ok(), "Address creation should succeed");

        let address = result.unwrap();

        // Address should be 40 hex characters (20 bytes * 2)
        assert_eq!(address.len(), 40, "Address should be 40 hex characters");

        // Should be valid hex
        assert!(hex::decode(&address).is_ok(), "Address should be valid hex");

        // Should be deterministic - same wallet should produce same address
        let address2 = wallet
            .create_address()
            .expect("Second address creation failed");
        assert_eq!(address, address2, "Same wallet should produce same address");
    }

    #[test]
    fn test_generate_address_from_public_key() {
        // Test address generation from public key
        let wallet = Wallet::new().expect("Failed to create wallet");
        let public_key = wallet.get_public_key();

        let result = generate_address_from_public_key(public_key);
        assert!(result.is_ok(), "Address generation should succeed");

        let address = result.unwrap();
        assert_eq!(address.len(), 40, "Address should be 40 hex characters");
        assert!(hex::decode(&address).is_ok(), "Address should be valid hex");

        // Should match wallet's create_address method
        let wallet_address = wallet
            .create_address()
            .expect("Wallet address creation failed");
        assert_eq!(
            address, wallet_address,
            "Both methods should produce same address"
        );
    }

    #[test]
    fn test_address_deterministic() {
        // Test that same public key always produces same address
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key = SecretKey::from_str(private_key_hex).expect("Failed to create test key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");

        let address1 = generate_address_from_public_key(&public_key).expect("First address failed");
        let address2 =
            generate_address_from_public_key(&public_key).expect("Second address failed");

        assert_eq!(
            address1, address2,
            "Same public key should produce same address"
        );
        assert_eq!(address1.len(), 40, "Address should be 40 hex characters");
    }

    #[test]
    fn test_different_keys_different_addresses() {
        // Test that different public keys produce different addresses
        let wallet1 = Wallet::new().expect("Failed to create first wallet");
        let wallet2 = Wallet::new().expect("Failed to create second wallet");

        let address1 = wallet1.create_address().expect("First address failed");
        let address2 = wallet2.create_address().expect("Second address failed");

        // Addresses should be different (extremely unlikely to be the same)
        assert_ne!(
            address1, address2,
            "Different wallets should have different addresses"
        );
    }

    #[test]
    fn test_validate_address_format_valid() {
        // Test validation with valid address
        let valid_address = "1234567890abcdef1234567890abcdef12345678";
        let result = validate_address_format(valid_address);

        assert!(result.is_ok(), "Valid address should pass validation");
    }

    #[test]
    fn test_validate_address_format_invalid_length() {
        // Test validation with invalid length
        let short_address = "1234567890abcdef1234567890abcdef123456";
        let result = validate_address_format(short_address);
        assert!(result.is_err(), "Short address should fail validation");

        let long_address = "1234567890abcdef1234567890abcdef1234567890";
        let result = validate_address_format(long_address);
        assert!(result.is_err(), "Long address should fail validation");
    }

    #[test]
    fn test_validate_address_format_invalid_hex() {
        // Test validation with invalid hex characters
        let invalid_hex = "g234567890abcdef1234567890abcdef12345678";
        let result = validate_address_format(invalid_hex);
        assert!(result.is_err(), "Invalid hex should fail validation");
    }

    #[test]
    fn test_format_address_with_prefix() {
        // Test address formatting with prefix
        let address = "1234567890abcdef1234567890abcdef12345678";
        let formatted = format_address(address, true);

        assert_eq!(formatted, "0x1234567890abcdef1234567890abcdef12345678");
        assert!(
            formatted.starts_with("0x"),
            "Formatted address should have 0x prefix"
        );
    }

    #[test]
    fn test_format_address_without_prefix() {
        // Test address formatting without prefix
        let address = "1234567890abcdef1234567890abcdef12345678";
        let formatted = format_address(address, false);

        assert_eq!(formatted, address);
        assert!(
            !formatted.starts_with("0x"),
            "Formatted address should not have 0x prefix"
        );
    }

    #[test]
    fn test_address_generation_with_known_key() {
        // Test address generation with a known private key for reproducible results
        let private_key_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let private_key = SecretKey::from_str(private_key_hex).expect("Failed to create test key");
        let public_key = derive_public_key(&private_key).expect("Failed to derive public key");

        let address =
            generate_address_from_public_key(&public_key).expect("Address generation failed");

        // Address should be deterministic for this specific key
        assert_eq!(address.len(), 40, "Address should be 40 hex characters");
        assert!(hex::decode(&address).is_ok(), "Address should be valid hex");

        // Test that it's reproducible
        let address2 =
            generate_address_from_public_key(&public_key).expect("Second generation failed");
        assert_eq!(
            address, address2,
            "Address generation should be deterministic"
        );
    }

    #[test]
    fn test_address_validation_integration() {
        // Test that generated addresses pass validation
        let wallet = Wallet::new().expect("Failed to create wallet");
        let address = wallet.create_address().expect("Failed to create address");

        let validation_result = validate_address_format(&address);
        assert!(
            validation_result.is_ok(),
            "Generated address should pass validation"
        );
    }

    #[test]
    fn test_address_error_handling() {
        // Test error cases for address functions
        let result = validate_address_format("invalid");
        assert!(result.is_err(), "Invalid address should fail validation");
        assert!(matches!(result.unwrap_err(), WalletError::AddressError(_)));

        let result = validate_address_format("123");
        assert!(result.is_err(), "Short address should fail validation");
        assert!(matches!(result.unwrap_err(), WalletError::AddressError(_)));
    }

    #[test]
    fn test_wallet_sign_message() {
        // Test message signing with wallet
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Hello, world!";

        let result = wallet.sign_message(message);
        assert!(result.is_ok(), "Message signing should succeed");

        let signature_hex = result.unwrap();
        assert_eq!(
            signature_hex.len(),
            128,
            "Signature should be 128 hex characters"
        );
        assert!(
            hex::decode(&signature_hex).is_ok(),
            "Signature should be valid hex"
        );
    }

    #[test]
    fn test_wallet_sign_string_message() {
        // Test string message signing with wallet
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = "Hello, world!";

        let result = wallet.sign_string_message(message);
        assert!(result.is_ok(), "String message signing should succeed");

        let signature_hex = result.unwrap();
        assert_eq!(
            signature_hex.len(),
            128,
            "Signature should be 128 hex characters"
        );

        // Should produce same result as byte array version
        let byte_signature = wallet
            .sign_message(message.as_bytes())
            .expect("Byte message signing failed");
        assert_eq!(
            signature_hex, byte_signature,
            "String and byte signing should match"
        );
    }

    #[test]
    fn test_wallet_sign_message_empty() {
        // Test signing empty message
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"";

        let result = wallet.sign_message(message);
        assert!(result.is_err(), "Empty message should return error");
        assert!(matches!(result.unwrap_err(), WalletError::SigningError(_)));
    }

    #[test]
    fn test_wallet_sign_message_deterministic() {
        // Test that same wallet and message produce same signature
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Deterministic test";

        let signature1 = wallet
            .sign_message(message)
            .expect("First signature failed");
        let signature2 = wallet
            .sign_message(message)
            .expect("Second signature failed");

        assert_eq!(
            signature1, signature2,
            "Same wallet and message should produce same signature"
        );
    }

    #[test]
    fn test_wallet_sign_different_messages() {
        // Test that different messages produce different signatures
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message1 = b"First message";
        let message2 = b"Second message";

        let signature1 = wallet
            .sign_message(message1)
            .expect("First signature failed");
        let signature2 = wallet
            .sign_message(message2)
            .expect("Second signature failed");

        assert_ne!(
            signature1, signature2,
            "Different messages should produce different signatures"
        );
    }

    #[test]
    fn test_wallet_sign_verify_integration() {
        // Test complete sign -> verify workflow using wallet
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Integration test message";

        // Sign the message
        let signature_hex = wallet
            .sign_message(message)
            .expect("Failed to sign message");

        // Parse the signature back
        let signature =
            crate::crypto::parse_signature_hex(&signature_hex).expect("Failed to parse signature");

        // Verify the signature
        let is_valid =
            crate::crypto::verify_signature(message, &signature, wallet.get_public_key())
                .expect("Failed to verify signature");

        assert!(is_valid, "Wallet signature should verify successfully");
    }

    #[test]
    fn test_different_wallets_different_signatures() {
        // Test that different wallets produce different signatures for same message
        let wallet1 = Wallet::new().expect("Failed to create first wallet");
        let wallet2 = Wallet::new().expect("Failed to create second wallet");
        let message = b"Same message";

        let signature1 = wallet1
            .sign_message(message)
            .expect("First signature failed");
        let signature2 = wallet2
            .sign_message(message)
            .expect("Second signature failed");

        // Different wallets should produce different signatures (extremely unlikely to be same)
        assert_ne!(
            signature1, signature2,
            "Different wallets should produce different signatures"
        );
    }

    #[test]
    fn test_wallet_verify_signature_valid() {
        // Test successful signature verification with wallet
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Test message for verification";

        // Sign the message
        let signature_hex = wallet
            .sign_message(message)
            .expect("Failed to sign message");

        // Verify the signature
        let result = wallet.verify_signature(message, &signature_hex);
        assert!(result.is_ok(), "Signature verification should succeed");
        assert!(result.unwrap(), "Valid signature should verify as true");
    }

    #[test]
    fn test_wallet_verify_signature_invalid() {
        // Test signature verification with wrong signature
        let wallet1 = Wallet::new().expect("Failed to create first wallet");
        let wallet2 = Wallet::new().expect("Failed to create second wallet");
        let message = b"Test message for verification";

        // Sign with wallet1
        let signature_hex = wallet1
            .sign_message(message)
            .expect("Failed to sign message");

        // Try to verify with wallet2's public key
        let result = wallet2.verify_signature(message, &signature_hex);
        assert!(result.is_ok(), "Verification should complete without error");
        assert!(!result.unwrap(), "Invalid signature should verify as false");
    }

    #[test]
    fn test_wallet_verify_signature_wrong_message() {
        // Test signature verification with wrong message
        let wallet = Wallet::new().expect("Failed to create wallet");
        let original_message = b"Original message";
        let different_message = b"Different message";

        // Sign the original message
        let signature_hex = wallet
            .sign_message(original_message)
            .expect("Failed to sign message");

        // Try to verify with different message
        let result = wallet.verify_signature(different_message, &signature_hex);
        assert!(result.is_ok(), "Verification should complete without error");
        assert!(
            !result.unwrap(),
            "Signature for different message should verify as false"
        );
    }

    #[test]
    fn test_wallet_verify_string_signature() {
        // Test string signature verification
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = "Test string message for verification";

        // Sign the string message
        let signature_hex = wallet
            .sign_string_message(message)
            .expect("Failed to sign string message");

        // Verify the string signature
        let result = wallet.verify_string_signature(message, &signature_hex);
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
    fn test_wallet_verify_signature_invalid_hex() {
        // Test verification with invalid signature hex
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Test message";
        let invalid_signature = "invalid_hex_signature";

        let result = wallet.verify_signature(message, invalid_signature);
        assert!(result.is_err(), "Invalid signature hex should return error");
        assert!(matches!(result.unwrap_err(), WalletError::InvalidInput(_)));
    }

    #[test]
    fn test_wallet_verify_signature_wrong_length() {
        // Test verification with wrong signature length
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Test message";
        let short_signature = "1234567890abcdef"; // Too short

        let result = wallet.verify_signature(message, short_signature);
        assert!(result.is_err(), "Short signature should return error");
        assert!(matches!(result.unwrap_err(), WalletError::InvalidInput(_)));
    }

    #[test]
    fn test_wallet_verify_signature_empty_message() {
        // Test verification with empty message
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"";
        let dummy_signature = "0".repeat(128); // Valid length but dummy content

        let result = wallet.verify_signature(message, &dummy_signature);
        assert!(result.is_err(), "Empty message should return error");
        assert!(matches!(result.unwrap_err(), WalletError::InvalidInput(_)));
    }

    #[test]
    fn test_wallet_sign_verify_round_trip() {
        // Test complete sign -> verify round trip with wallet methods
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Round trip test message";

        // Sign the message
        let signature_hex = wallet
            .sign_message(message)
            .expect("Failed to sign message");

        // Verify the signature
        let is_valid = wallet
            .verify_signature(message, &signature_hex)
            .expect("Failed to verify signature");

        assert!(is_valid, "Round trip signature should be valid");
    }

    #[test]
    fn test_wallet_string_sign_verify_round_trip() {
        // Test complete string sign -> verify round trip
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = "String round trip test message";

        // Sign the string message
        let signature_hex = wallet
            .sign_string_message(message)
            .expect("Failed to sign string message");

        // Verify the string signature
        let is_valid = wallet
            .verify_string_signature(message, &signature_hex)
            .expect("Failed to verify string signature");

        assert!(is_valid, "String round trip signature should be valid");
    }

    #[test]
    fn test_wallet_verify_signature_deterministic() {
        // Test that verification is deterministic
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Deterministic verification test";

        // Sign the message
        let signature_hex = wallet
            .sign_message(message)
            .expect("Failed to sign message");

        // Verify multiple times
        let result1 = wallet
            .verify_signature(message, &signature_hex)
            .expect("First verification failed");
        let result2 = wallet
            .verify_signature(message, &signature_hex)
            .expect("Second verification failed");

        assert_eq!(result1, result2, "Verification should be deterministic");
        assert!(result1, "Signature should be valid");
    }

    #[test]
    fn test_wallet_verify_signature_comprehensive_validation() {
        // Test comprehensive input validation for verification
        let wallet = Wallet::new().expect("Failed to create wallet");
        let message = b"Validation test message";

        // Test various invalid signature formats
        let invalid_hex_chars = "g".repeat(128);
        let too_short = "1".repeat(127);
        let too_long = "1".repeat(129);

        let test_cases = vec![
            ("", "Empty signature"),
            ("123", "Too short signature"),
            (invalid_hex_chars.as_str(), "Invalid hex characters"),
            (too_short.as_str(), "One character too short"),
            (too_long.as_str(), "One character too long"),
        ];

        for (invalid_sig, description) in test_cases {
            let result = wallet.verify_signature(message, invalid_sig);
            assert!(
                result.is_err(),
                "Should fail for {}: {}",
                description,
                invalid_sig
            );
        }
    }

    #[test]
    fn test_wallet_verify_cross_wallet_signatures() {
        // Test that signatures from one wallet don't verify with another wallet
        let wallet1 = Wallet::new().expect("Failed to create first wallet");
        let wallet2 = Wallet::new().expect("Failed to create second wallet");
        let message = b"Cross wallet test message";

        // Sign with wallet1
        let signature_hex = wallet1
            .sign_message(message)
            .expect("Failed to sign with wallet1");

        // Verify with wallet1 (should succeed)
        let result1 = wallet1
            .verify_signature(message, &signature_hex)
            .expect("Failed to verify with wallet1");
        assert!(result1, "Signature should verify with signing wallet");

        // Verify with wallet2 (should fail)
        let result2 = wallet2
            .verify_signature(message, &signature_hex)
            .expect("Failed to verify with wallet2");
        assert!(
            !result2,
            "Signature should not verify with different wallet"
        );
    }
}
