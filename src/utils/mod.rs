// src/utils/mod.rs
pub mod formatting;
pub mod validation;

// Re-export commonly used functions
pub use formatting::{
    format_address, format_address_display, format_key_display, format_private_key,
    format_public_key, format_signature, is_valid_hex, normalize_hex, parse_address_hex,
    parse_private_key_hex, parse_public_key_hex, parse_signature_hex,
};

pub use validation::{
    is_safe_for_file_ops, sanitize_cli_input, validate_address_input, validate_crypto_inputs,
    validate_message_input, validate_non_empty_params, validate_parameter_count,
    validate_private_key_input, validate_public_key_input, validate_signature_input,
};
