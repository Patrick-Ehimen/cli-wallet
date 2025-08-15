//! Error handling for the CLI wallet application
//!
//! This module defines all possible errors that can occur in the wallet
//! and provides user-friendly error messages and conversion utilities.

use std::fmt;

/// Main error type for the wallet application
///
/// This enum represents all possible errors that can occur during wallet operations.
/// Each variant corresponds to a different category of error with specific context.
#[derive(Debug, Clone, PartialEq)]
pub enum WalletError {
    /// Errors that occur during cryptographic key generation
    ///
    /// Examples: Random number generation failure, invalid key parameters
    KeyGenerationError(String),

    /// Errors that occur during message signing operations
    ///
    /// Examples: Invalid private key, malformed message, signing algorithm failure
    SigningError(String),

    /// Errors that occur during signature verification
    ///
    /// Examples: Invalid signature format, verification algorithm failure
    VerificationError(String),

    /// Errors caused by invalid user input
    ///
    /// Examples: Malformed hex strings, empty required parameters
    InvalidInput(String),

    /// Low-level cryptographic errors from external libraries
    ///
    /// Examples: secp256k1 library errors, hashing failures
    CryptoError(String),

    /// Errors related to address generation and formatting
    ///
    /// Examples: Invalid public key for address generation, encoding failures
    AddressError(String),
}

/// Implementation of Display trait for user-friendly error messages
///
/// This provides human-readable error messages that will be shown to users.
/// Each error type has a clear prefix and helpful context.
impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::KeyGenerationError(msg) => {
                write!(f, "Key Generation Error: {}", msg)
            }
            WalletError::SigningError(msg) => {
                write!(f, "Signing Error: {}", msg)
            }
            WalletError::VerificationError(msg) => {
                write!(f, "Verification Error: {}", msg)
            }
            WalletError::InvalidInput(msg) => {
                write!(f, "Invalid Input: {}", msg)
            }
            WalletError::CryptoError(msg) => {
                write!(f, "Cryptographic Error: {}", msg)
            }
            WalletError::AddressError(msg) => {
                write!(f, "Address Error: {}", msg)
            }
        }
    }
}
/// Implementation of std::error::Error trait
///
/// This makes WalletError compatible with Rust's error handling ecosystem
/// and allows it to be used with the ? operator and error propagation.
impl std::error::Error for WalletError {
    fn description(&self) -> &str {
        match self {
            WalletError::KeyGenerationError(_) => "Failed to generate cryptographic keys",
            WalletError::SigningError(_) => "Failed to sign message",
            WalletError::VerificationError(_) => "Failed to verify signature",
            WalletError::InvalidInput(_) => "Invalid input provided",
            WalletError::CryptoError(_) => "Cryptographic operation failed",
            WalletError::AddressError(_) => "Address operation failed",
        }
    }
}
/// Conversion from secp256k1 errors
///
/// The secp256k1 library can fail in various ways (invalid keys, signing failures, etc.)
/// We convert these to our domain-specific error types for better user experience.
impl From<secp256k1::Error> for WalletError {
    fn from(err: secp256k1::Error) -> Self {
        match err {
            secp256k1::Error::InvalidPublicKey => {
                WalletError::CryptoError("Invalid public key format".to_string())
            }
            secp256k1::Error::InvalidSecretKey => {
                WalletError::CryptoError("Invalid private key format".to_string())
            }
            secp256k1::Error::InvalidSignature => {
                WalletError::VerificationError("Invalid signature format".to_string())
            }
            secp256k1::Error::InvalidMessage => {
                WalletError::SigningError("Invalid message for signing".to_string())
            }
            _ => WalletError::CryptoError(format!("Secp256k1 error: {}", err)),
        }
    }
}

/// Conversion from hex decoding errors
///
/// When users provide hex-encoded keys or signatures, decoding can fail.
/// We convert these to user-friendly input validation errors.
impl From<hex::FromHexError> for WalletError {
    fn from(err: hex::FromHexError) -> Self {
        WalletError::InvalidInput(format!("Invalid hex format: {}", err))
    }
}
/// Type alias for Results using WalletError
///
/// This makes function signatures cleaner and more consistent throughout the codebase.
/// Instead of writing Result<T, WalletError> everywhere, we can use WalletResult<T>.
pub type WalletResult<T> = Result<T, WalletError>;

/// Utility functions for creating specific error types
impl WalletError {
    /// Create a key generation error with context
    pub fn key_generation<S: Into<String>>(msg: S) -> Self {
        WalletError::KeyGenerationError(msg.into())
    }

    /// Create a signing error with context
    pub fn signing<S: Into<String>>(msg: S) -> Self {
        WalletError::SigningError(msg.into())
    }

    /// Create a verification error with context
    pub fn verification<S: Into<String>>(msg: S) -> Self {
        WalletError::VerificationError(msg.into())
    }

    /// Create an invalid input error with context
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        WalletError::InvalidInput(msg.into())
    }

    /// Create a crypto error with context
    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        WalletError::CryptoError(msg.into())
    }

    /// Create an address error with context
    pub fn address<S: Into<String>>(msg: S) -> Self {
        WalletError::AddressError(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_formatting() {
        let key_error =
            WalletError::KeyGenerationError("Failed to generate random key".to_string());
        assert_eq!(
            key_error.to_string(),
            "Key Generation Error: Failed to generate random key"
        );

        let signing_error = WalletError::SigningError("Private key is invalid".to_string());
        assert_eq!(
            signing_error.to_string(),
            "Signing Error: Private key is invalid"
        );

        let verification_error =
            WalletError::VerificationError("Signature does not match".to_string());
        assert_eq!(
            verification_error.to_string(),
            "Verification Error: Signature does not match"
        );

        let input_error = WalletError::InvalidInput("Hex string is malformed".to_string());
        assert_eq!(
            input_error.to_string(),
            "Invalid Input: Hex string is malformed"
        );

        let crypto_error = WalletError::CryptoError("Secp256k1 operation failed".to_string());
        assert_eq!(
            crypto_error.to_string(),
            "Cryptographic Error: Secp256k1 operation failed"
        );

        let address_error = WalletError::AddressError("Cannot generate address".to_string());
        assert_eq!(
            address_error.to_string(),
            "Address Error: Cannot generate address"
        );
    }

    #[test]
    fn test_error_utility_functions() {
        let key_error = WalletError::key_generation("Test key error");
        assert!(matches!(key_error, WalletError::KeyGenerationError(_)));

        let signing_error = WalletError::signing("Test signing error");
        assert!(matches!(signing_error, WalletError::SigningError(_)));

        let verification_error = WalletError::verification("Test verification error");
        assert!(matches!(
            verification_error,
            WalletError::VerificationError(_)
        ));

        let input_error = WalletError::invalid_input("Test input error");
        assert!(matches!(input_error, WalletError::InvalidInput(_)));

        let crypto_error = WalletError::crypto("Test crypto error");
        assert!(matches!(crypto_error, WalletError::CryptoError(_)));

        let address_error = WalletError::address("Test address error");
        assert!(matches!(address_error, WalletError::AddressError(_)));
    }

    #[test]
    fn test_secp256k1_error_conversion() {
        let secp_error = secp256k1::Error::InvalidPublicKey;
        let wallet_error: WalletError = secp_error.into();
        assert!(matches!(wallet_error, WalletError::CryptoError(_)));
        assert_eq!(
            wallet_error.to_string(),
            "Cryptographic Error: Invalid public key format"
        );

        let secp_error = secp256k1::Error::InvalidSecretKey;
        let wallet_error: WalletError = secp_error.into();
        assert!(matches!(wallet_error, WalletError::CryptoError(_)));

        let secp_error = secp256k1::Error::InvalidSignature;
        let wallet_error: WalletError = secp_error.into();
        assert!(matches!(wallet_error, WalletError::VerificationError(_)));
    }

    #[test]
    fn test_hex_error_conversion() {
        // Create an invalid hex string to trigger FromHexError
        let hex_result = hex::decode("invalid_hex_string");
        assert!(hex_result.is_err());

        if let Err(hex_error) = hex_result {
            let wallet_error: WalletError = hex_error.into();
            assert!(matches!(wallet_error, WalletError::InvalidInput(_)));
            assert!(wallet_error.to_string().contains("Invalid hex format"));
        }
    }

    #[test]
    fn test_error_equality() {
        let error1 = WalletError::KeyGenerationError("Same message".to_string());
        let error2 = WalletError::KeyGenerationError("Same message".to_string());
        let error3 = WalletError::KeyGenerationError("Different message".to_string());

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_wallet_result_type_alias() {
        // Test that our type alias works correctly
        fn example_function() -> WalletResult<String> {
            Ok("Success".to_string())
        }

        fn example_error_function() -> WalletResult<String> {
            Err(WalletError::invalid_input("Test error"))
        }

        assert!(example_function().is_ok());
        assert!(example_error_function().is_err());
    }
}
