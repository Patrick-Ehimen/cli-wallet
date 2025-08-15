//! Input validation and sanitization utilities
//!
//! This module provides functions for validating and sanitizing user inputs
//! to ensure they meet the requirements for cryptographic operations.

use crate::error::{WalletError, WalletResult};
use crate::utils::formatting::{is_valid_hex, normalize_hex};

/// Validate a hex string for private key format
///
/// Checks that the input is a valid 64-character hex string suitable for a private key.
///
/// # Arguments
///
/// * `input` - The input string to validate
///
/// # Returns
///
/// * `WalletResult<String>` - The normalized hex string or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::validate_private_key_input;
///
/// let result = validate_private_key_input("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
/// assert!(result.is_ok());
/// ```
pub fn validate_private_key_input(input: &str) -> WalletResult<String> {
    // Check for empty input
    if input.trim().is_empty() {
        return Err(WalletError::invalid_input("Private key cannot be empty"));
    }

    // Normalize the hex string (remove prefix, convert to lowercase)
    let normalized = normalize_hex(input.trim());

    // Check length (64 hex characters = 32 bytes)
    if normalized.len() != 64 {
        return Err(WalletError::invalid_input(format!(
            "Private key must be 64 hex characters, got {}",
            normalized.len()
        )));
    }

    // Check for valid hex characters
    if !is_valid_hex(&normalized) {
        return Err(WalletError::invalid_input(
            "Private key contains invalid hex characters",
        ));
    }

    // Check that it's not all zeros (invalid private key)
    if normalized == "0".repeat(64) {
        return Err(WalletError::invalid_input(
            "Private key cannot be all zeros",
        ));
    }

    // Check that it's not all ones (invalid private key)
    if normalized == "f".repeat(64) {
        return Err(WalletError::invalid_input("Private key cannot be all ones"));
    }

    Ok(normalized)
}

/// Validate a hex string for public key format
///
/// Checks that the input is a valid hex string suitable for a public key.
/// Supports both compressed (66 chars) and uncompressed (130 chars) formats.
///
/// # Arguments
///
/// * `input` - The input string to validate
///
/// # Returns
///
/// * `WalletResult<String>` - The normalized hex string or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::validate_public_key_input;
///
/// // Compressed format
/// let test_key = format!("02{}", "0".repeat(62));
/// let result = validate_public_key_input(&test_key);
/// assert!(result.is_ok());
/// ```
pub fn validate_public_key_input(input: &str) -> WalletResult<String> {
    // Check for empty input
    if input.trim().is_empty() {
        return Err(WalletError::invalid_input("Public key cannot be empty"));
    }

    // Normalize the hex string
    let normalized = normalize_hex(input.trim());

    // Check length (66 for compressed, 130 for uncompressed)
    if normalized.len() != 66 && normalized.len() != 130 {
        return Err(WalletError::invalid_input(format!(
            "Public key must be 66 (compressed) or 130 (uncompressed) hex characters, got {}",
            normalized.len()
        )));
    }

    // Check for valid hex characters
    if !is_valid_hex(&normalized) {
        return Err(WalletError::invalid_input(
            "Public key contains invalid hex characters",
        ));
    }

    // Check format prefix for compressed keys
    if normalized.len() == 66 {
        let prefix = &normalized[..2];
        if prefix != "02" && prefix != "03" {
            return Err(WalletError::invalid_input(
                "Compressed public key must start with 02 or 03",
            ));
        }
    }

    // Check format prefix for uncompressed keys
    if normalized.len() == 130 {
        let prefix = &normalized[..2];
        if prefix != "04" {
            return Err(WalletError::invalid_input(
                "Uncompressed public key must start with 04",
            ));
        }
    }

    Ok(normalized)
}

/// Validate a hex string for signature format
///
/// Checks that the input is a valid 128-character hex string suitable for a signature.
///
/// # Arguments
///
/// * `input` - The input string to validate
///
/// # Returns
///
/// * `WalletResult<String>` - The normalized hex string or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::validate_signature_input;
///
/// let signature_hex = "0".repeat(128);
/// let result = validate_signature_input(&signature_hex);
/// assert!(result.is_ok());
/// ```
pub fn validate_signature_input(input: &str) -> WalletResult<String> {
    // Check for empty input
    if input.trim().is_empty() {
        return Err(WalletError::invalid_input("Signature cannot be empty"));
    }

    // Normalize the hex string
    let normalized = normalize_hex(input.trim());

    // Check length (128 hex characters = 64 bytes)
    if normalized.len() != 128 {
        return Err(WalletError::invalid_input(format!(
            "Signature must be 128 hex characters, got {}",
            normalized.len()
        )));
    }

    // Check for valid hex characters
    if !is_valid_hex(&normalized) {
        return Err(WalletError::invalid_input(
            "Signature contains invalid hex characters",
        ));
    }

    Ok(normalized)
}

/// Validate a message input for signing/verification
///
/// Checks that the message is valid for cryptographic operations.
///
/// # Arguments
///
/// * `input` - The message string to validate
///
/// # Returns
///
/// * `WalletResult<String>` - The validated message or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::validate_message_input;
///
/// let result = validate_message_input("Hello, world!");
/// assert!(result.is_ok());
/// ```
pub fn validate_message_input(input: &str) -> WalletResult<String> {
    // Check for empty input
    if input.is_empty() {
        return Err(WalletError::invalid_input("Message cannot be empty"));
    }

    // Check message length (reasonable limit for CLI usage)
    const MAX_MESSAGE_LENGTH: usize = 1024 * 1024; // 1MB
    if input.len() > MAX_MESSAGE_LENGTH {
        return Err(WalletError::invalid_input(format!(
            "Message too long: {} bytes (max: {} bytes)",
            input.len(),
            MAX_MESSAGE_LENGTH
        )));
    }

    // Check for null bytes (can cause issues in some contexts)
    if input.contains('\0') {
        return Err(WalletError::invalid_input(
            "Message cannot contain null bytes",
        ));
    }

    // Message is valid as-is (no normalization needed for messages)
    Ok(input.to_string())
}

/// Validate an address input
///
/// Checks that the input is a valid hex string suitable for an address.
///
/// # Arguments
///
/// * `input` - The address string to validate
///
/// # Returns
///
/// * `WalletResult<String>` - The normalized address hex string or an error
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::validate_address_input;
///
/// let result = validate_address_input("0x1234567890abcdef1234567890abcdef12345678");
/// assert!(result.is_ok());
/// ```
pub fn validate_address_input(input: &str) -> WalletResult<String> {
    // Check for empty input
    if input.trim().is_empty() {
        return Err(WalletError::invalid_input("Address cannot be empty"));
    }

    // Normalize the hex string
    let normalized = normalize_hex(input.trim());

    // Check for valid hex characters
    if !is_valid_hex(&normalized) {
        return Err(WalletError::invalid_input(
            "Address contains invalid hex characters",
        ));
    }

    // Check that length is even (hex strings must have even number of characters)
    if normalized.len() % 2 != 0 {
        return Err(WalletError::invalid_input(
            "Address hex string must have even number of characters",
        ));
    }

    // Check reasonable length bounds (addresses are typically 20 bytes = 40 hex chars)
    if normalized.len() < 8 || normalized.len() > 80 {
        return Err(WalletError::invalid_input(format!(
            "Address length {} is outside reasonable bounds (8-80 characters)",
            normalized.len()
        )));
    }

    Ok(normalized)
}

/// Sanitize command line input by removing dangerous characters
///
/// Removes or escapes characters that could be problematic in CLI contexts.
///
/// # Arguments
///
/// * `input` - The input string to sanitize
///
/// # Returns
///
/// * `String` - The sanitized input string
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::sanitize_cli_input;
///
/// let sanitized = sanitize_cli_input("hello\nworld\t!");
/// assert!(!sanitized.contains('\n'));
/// ```
pub fn sanitize_cli_input(input: &str) -> String {
    input
        .chars()
        .filter(|&c| {
            // Keep printable ASCII characters and common whitespace
            c.is_ascii_graphic() || c == ' '
        })
        .collect()
}

/// Validate parameter count for commands
///
/// Checks that the correct number of parameters are provided for a command.
///
/// # Arguments
///
/// * `params` - The parameter vector to validate
/// * `expected_min` - Minimum number of expected parameters
/// * `expected_max` - Maximum number of expected parameters (None for no limit)
/// * `command_name` - Name of the command for error messages
///
/// # Returns
///
/// * `WalletResult<()>` - Ok if parameter count is valid, error otherwise
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::validate_parameter_count;
///
/// let params = vec!["param1".to_string(), "param2".to_string()];
/// let result = validate_parameter_count(&params, 2, Some(2), "test_command");
/// assert!(result.is_ok());
/// ```
pub fn validate_parameter_count(
    params: &[String],
    expected_min: usize,
    expected_max: Option<usize>,
    command_name: &str,
) -> WalletResult<()> {
    let count = params.len();

    if count < expected_min {
        return Err(WalletError::invalid_input(format!(
            "Command '{}' requires at least {} parameters, got {}",
            command_name, expected_min, count
        )));
    }

    if let Some(max) = expected_max {
        if count > max {
            return Err(WalletError::invalid_input(format!(
                "Command '{}' accepts at most {} parameters, got {}",
                command_name, max, count
            )));
        }
    }

    Ok(())
}

/// Validate that all required parameters are non-empty
///
/// Checks that all provided parameters contain meaningful content.
///
/// # Arguments
///
/// * `params` - The parameter vector to validate
/// * `param_names` - Names of the parameters for error messages
///
/// # Returns
///
/// * `WalletResult<()>` - Ok if all parameters are valid, error otherwise
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::validate_non_empty_params;
///
/// let params = vec!["value1".to_string(), "value2".to_string()];
/// let names = vec!["param1", "param2"];
/// let result = validate_non_empty_params(&params, &names);
/// assert!(result.is_ok());
/// ```
pub fn validate_non_empty_params(params: &[String], param_names: &[&str]) -> WalletResult<()> {
    for (i, param) in params.iter().enumerate() {
        if param.trim().is_empty() {
            let param_name = param_names.get(i).unwrap_or(&"parameter");
            return Err(WalletError::invalid_input(format!(
                "{} cannot be empty",
                param_name
            )));
        }
    }
    Ok(())
}

/// Comprehensive input validation for cryptographic operations
///
/// Validates all inputs for a complete sign/verify operation.
///
/// # Arguments
///
/// * `message` - The message to validate
/// * `private_key_hex` - Optional private key hex string
/// * `public_key_hex` - Optional public key hex string
/// * `signature_hex` - Optional signature hex string
///
/// # Returns
///
/// * `WalletResult<()>` - Ok if all provided inputs are valid, error otherwise
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::validate_crypto_inputs;
///
/// let result = validate_crypto_inputs(
///     Some("Hello, world!"),
///     Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
///     None,
///     None
/// );
/// assert!(result.is_ok());
/// ```
pub fn validate_crypto_inputs(
    message: Option<&str>,
    private_key_hex: Option<&str>,
    public_key_hex: Option<&str>,
    signature_hex: Option<&str>,
) -> WalletResult<()> {
    // Validate message if provided
    if let Some(msg) = message {
        validate_message_input(msg)?;
    }

    // Validate private key if provided
    if let Some(priv_key) = private_key_hex {
        validate_private_key_input(priv_key)?;
    }

    // Validate public key if provided
    if let Some(pub_key) = public_key_hex {
        validate_public_key_input(pub_key)?;
    }

    // Validate signature if provided
    if let Some(sig) = signature_hex {
        validate_signature_input(sig)?;
    }

    Ok(())
}

/// Check if input contains only safe characters for file operations
///
/// Validates that input doesn't contain characters that could be problematic
/// for file operations or path traversal attacks.
///
/// # Arguments
///
/// * `input` - The input string to validate
///
/// # Returns
///
/// * `bool` - True if input is safe, false otherwise
///
/// # Examples
///
/// ```
/// use cli_wallet::utils::validation::is_safe_for_file_ops;
///
/// assert!(is_safe_for_file_ops("safe_filename"));
/// assert!(!is_safe_for_file_ops("../dangerous"));
/// ```
pub fn is_safe_for_file_ops(input: &str) -> bool {
    // Check for path traversal attempts
    if input.contains("..") || input.contains("/") || input.contains("\\") {
        return false;
    }

    // Check for null bytes
    if input.contains('\0') {
        return false;
    }

    // Check for control characters
    if input.chars().any(|c| c.is_control()) {
        return false;
    }

    // Check for reserved names on Windows
    let reserved_names = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    let upper_input = input.to_uppercase();
    if reserved_names.iter().any(|&name| upper_input == name) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_private_key_input_valid() {
        let valid_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = validate_private_key_input(valid_key);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_key);
    }

    #[test]
    fn test_validate_private_key_input_with_prefix() {
        let key_with_prefix = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = validate_private_key_input(key_with_prefix);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_validate_private_key_input_empty() {
        let result = validate_private_key_input("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WalletError::InvalidInput(_)));
    }

    #[test]
    fn test_validate_private_key_input_wrong_length() {
        let short_key = "0123456789abcdef";
        let result = validate_private_key_input(short_key);
        assert!(result.is_err());

        let long_key = "0123456789abcdef".repeat(5);
        let result = validate_private_key_input(&long_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_private_key_input_invalid_hex() {
        let invalid_key = "g".repeat(64);
        let result = validate_private_key_input(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_private_key_input_all_zeros() {
        let zero_key = "0".repeat(64);
        let result = validate_private_key_input(&zero_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_private_key_input_all_ones() {
        let ones_key = "f".repeat(64);
        let result = validate_private_key_input(&ones_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_public_key_input_compressed() {
        let compressed_key = format!("02{}", "0".repeat(64));
        let result = validate_public_key_input(&compressed_key);
        assert!(result.is_ok());

        let compressed_key2 = format!("03{}", "0".repeat(64));
        let result2 = validate_public_key_input(&compressed_key2);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_validate_public_key_input_uncompressed() {
        let uncompressed_key = format!("04{}", "0".repeat(128));
        let result = validate_public_key_input(&uncompressed_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_public_key_input_invalid_prefix() {
        let invalid_compressed = format!("01{}", "0".repeat(64));
        let result = validate_public_key_input(&invalid_compressed);
        assert!(result.is_err());

        let invalid_uncompressed = format!("05{}", "0".repeat(128));
        let result2 = validate_public_key_input(&invalid_uncompressed);
        assert!(result2.is_err());
    }

    #[test]
    fn test_validate_public_key_input_wrong_length() {
        let wrong_length = format!("02{}", "0".repeat(60));
        let result = validate_public_key_input(&wrong_length);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_signature_input_valid() {
        let valid_signature = "0".repeat(128);
        let result = validate_signature_input(&valid_signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_signature_input_wrong_length() {
        let short_signature = "0".repeat(64);
        let result = validate_signature_input(&short_signature);
        assert!(result.is_err());

        let long_signature = "0".repeat(256);
        let result2 = validate_signature_input(&long_signature);
        assert!(result2.is_err());
    }

    #[test]
    fn test_validate_message_input_valid() {
        let valid_message = "Hello, world!";
        let result = validate_message_input(valid_message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_message);
    }

    #[test]
    fn test_validate_message_input_empty() {
        let result = validate_message_input("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_message_input_too_long() {
        let long_message = "a".repeat(1024 * 1024 + 1);
        let result = validate_message_input(&long_message);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_message_input_null_bytes() {
        let message_with_null = "Hello\0world";
        let result = validate_message_input(message_with_null);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_address_input_valid() {
        let valid_address = "1234567890abcdef1234567890abcdef12345678";
        let result = validate_address_input(valid_address);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_address_input_with_prefix() {
        let address_with_prefix = "0x1234567890abcdef1234567890abcdef12345678";
        let expected = "1234567890abcdef1234567890abcdef12345678";
        let result = validate_address_input(address_with_prefix);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_validate_address_input_odd_length() {
        let odd_address = "123";
        let result = validate_address_input(odd_address);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_address_input_wrong_length() {
        let too_short = "1234";
        let result = validate_address_input(too_short);
        assert!(result.is_err());

        let too_long = "1".repeat(100);
        let result2 = validate_address_input(&too_long);
        assert!(result2.is_err());
    }

    #[test]
    fn test_sanitize_cli_input() {
        let input = "hello\nworld\t!@#$%^&*()";
        let sanitized = sanitize_cli_input(input);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\t'));
        assert!(sanitized.contains('!'));
        assert!(sanitized.contains('@'));
    }

    #[test]
    fn test_validate_parameter_count_valid() {
        let params = vec!["param1".to_string(), "param2".to_string()];
        let result = validate_parameter_count(&params, 2, Some(2), "test_command");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_parameter_count_too_few() {
        let params = vec!["param1".to_string()];
        let result = validate_parameter_count(&params, 2, Some(3), "test_command");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_parameter_count_too_many() {
        let params = vec![
            "param1".to_string(),
            "param2".to_string(),
            "param3".to_string(),
        ];
        let result = validate_parameter_count(&params, 1, Some(2), "test_command");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_parameter_count_no_max() {
        let params = vec![
            "param1".to_string(),
            "param2".to_string(),
            "param3".to_string(),
        ];
        let result = validate_parameter_count(&params, 1, None, "test_command");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_non_empty_params_valid() {
        let params = vec!["value1".to_string(), "value2".to_string()];
        let names = vec!["param1", "param2"];
        let result = validate_non_empty_params(&params, &names);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_non_empty_params_empty() {
        let params = vec!["value1".to_string(), "".to_string()];
        let names = vec!["param1", "param2"];
        let result = validate_non_empty_params(&params, &names);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_non_empty_params_whitespace() {
        let params = vec!["value1".to_string(), "   ".to_string()];
        let names = vec!["param1", "param2"];
        let result = validate_non_empty_params(&params, &names);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_crypto_inputs_all_valid() {
        let public_key = format!("02{}", "0".repeat(64));
        let signature = "0".repeat(128);
        let result = validate_crypto_inputs(
            Some("Hello, world!"),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            Some(&public_key),
            Some(&signature),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_crypto_inputs_partial() {
        let result = validate_crypto_inputs(
            Some("Hello, world!"),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            None,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_crypto_inputs_invalid_message() {
        let result = validate_crypto_inputs(
            Some(""),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_is_safe_for_file_ops_safe() {
        assert!(is_safe_for_file_ops("safe_filename"));
        assert!(is_safe_for_file_ops("file123"));
        assert!(is_safe_for_file_ops("my-file_name.txt"));
    }

    #[test]
    fn test_is_safe_for_file_ops_path_traversal() {
        assert!(!is_safe_for_file_ops("../dangerous"));
        assert!(!is_safe_for_file_ops("path/to/file"));
        assert!(!is_safe_for_file_ops("path\\to\\file"));
    }

    #[test]
    fn test_is_safe_for_file_ops_null_bytes() {
        assert!(!is_safe_for_file_ops("file\0name"));
    }

    #[test]
    fn test_is_safe_for_file_ops_control_chars() {
        assert!(!is_safe_for_file_ops("file\nname"));
        assert!(!is_safe_for_file_ops("file\tname"));
    }

    #[test]
    fn test_is_safe_for_file_ops_reserved_names() {
        assert!(!is_safe_for_file_ops("CON"));
        assert!(!is_safe_for_file_ops("con"));
        assert!(!is_safe_for_file_ops("PRN"));
        assert!(!is_safe_for_file_ops("NUL"));
        assert!(!is_safe_for_file_ops("COM1"));
        assert!(!is_safe_for_file_ops("LPT1"));
    }

    #[test]
    fn test_input_validation_edge_cases() {
        // Test whitespace handling
        let result = validate_private_key_input(
            "  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ",
        );
        assert!(result.is_ok());

        // Test case insensitive hex
        let result = validate_private_key_input(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn test_comprehensive_validation_workflow() {
        // Test a complete validation workflow
        let message = "Test message for signing";
        let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let public_key = format!("02{}", "0".repeat(64));
        let signature = "0".repeat(128);

        // Validate each component individually
        assert!(validate_message_input(message).is_ok());
        assert!(validate_private_key_input(private_key).is_ok());
        assert!(validate_public_key_input(&public_key).is_ok());
        assert!(validate_signature_input(&signature).is_ok());

        // Validate all together
        assert!(
            validate_crypto_inputs(
                Some(message),
                Some(private_key),
                Some(&public_key),
                Some(&signature)
            )
            .is_ok()
        );
    }

    #[test]
    fn test_error_message_quality() {
        // Test that error messages are informative
        let result = validate_private_key_input("short");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("64 hex characters"));
        assert!(error_msg.contains("got 5"));

        let result = validate_parameter_count(&[], 2, Some(3), "sign");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("sign"));
        assert!(error_msg.contains("at least 2"));
    }
}
