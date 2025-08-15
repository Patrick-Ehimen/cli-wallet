# CLI Wallet API Documentation

This document provides comprehensive documentation for the CLI Wallet library's public API. The library is organized into several modules, each providing specific functionality for cryptocurrency wallet operations.

## Table of Contents

- [Overview](#overview)
- [Core Types](#core-types)
- [Wallet Module](#wallet-module)
- [Crypto Module](#crypto-module)
- [CLI Module](#cli-module)
- [Error Handling](#error-handling)
- [Usage Examples](#usage-examples)

## Overview

The CLI Wallet library provides a complete implementation of basic cryptocurrency wallet functionality using the secp256k1 elliptic curve. It's designed for educational purposes and demonstrates proper cryptographic practices.

### Key Features

- **Secure Key Generation**: Cryptographically secure random key generation
- **Message Signing**: ECDSA signature creation with SHA-256 message hashing
- **Signature Verification**: Cryptographic signature validation
- **Address Generation**: Wallet address creation from public keys
- **CLI Interface**: User-friendly command-line interface
- **Comprehensive Error Handling**: Detailed error messages and validation

## Core Types

### WalletError

The main error type used throughout the library.

```rust
pub enum WalletError {
    KeyGenerationError(String),
    SigningError(String),
    VerificationError(String),
    InvalidInput(String),
    CryptoError(String),
    AddressError(String),
}
```

### WalletResult<T>

Type alias for Results using WalletError:

```rust
pub type WalletResult<T> = Result<T, WalletError>;
```

## Wallet Module

The wallet module provides the main `Wallet` struct and related functionality.

### Wallet Struct

```rust
pub struct Wallet {
    private_key: SecretKey,
    public_key: PublicKey,
}
```

#### Methods

##### `new() -> Result<Wallet, WalletError>`

Creates a new wallet with a randomly generated key pair.

```rust
use cli_wallet::Wallet;

let wallet = Wallet::new()?;
```

**Returns:**

- `Ok(Wallet)` - A new wallet instance
- `Err(WalletError)` - If key generation fails

**Security Notes:**

- Uses cryptographically secure random number generation
- Private key is automatically validated
- Public key is derived using elliptic curve multiplication

##### `generate_keypair(&self) -> Result<(String, String), WalletError>`

Returns the wallet's keys as hex-encoded strings.

```rust
let (private_hex, public_hex) = wallet.generate_keypair()?;
println!("Private Key: {}", private_hex); // 64 hex characters
println!("Public Key: {}", public_hex);   // 66 hex characters (compressed)
```

**Returns:**

- `Ok((String, String))` - Tuple of (private_key_hex, public_key_hex)
- `Err(WalletError)` - If formatting fails

##### `create_address(&self) -> Result<String, WalletError>`

Generates a wallet address from the public key.

```rust
let address = wallet.create_address()?;
println!("Address: 0x{}", address); // 40 hex characters
```

**Returns:**

- `Ok(String)` - The wallet address as a hex string
- `Err(WalletError)` - If address generation fails

**Algorithm:**

1. Take the compressed public key (33 bytes)
2. Hash with SHA-256
3. Take the first 20 bytes
4. Encode as hexadecimal

##### `sign_message(&self, message: &[u8]) -> Result<String, WalletError>`

Signs a message using the wallet's private key.

```rust
let message = b"Hello, world!";
let signature = wallet.sign_message(message)?;
println!("Signature: {}", signature); // 128 hex characters
```

**Parameters:**

- `message` - The message bytes to sign

**Returns:**

- `Ok(String)` - The signature as a hex string
- `Err(WalletError)` - If signing fails

**Process:**

1. Hash the message with SHA-256
2. Sign the hash using ECDSA with secp256k1
3. Format the signature as DER-encoded hex

##### `sign_string_message(&self, message: &str) -> Result<String, WalletError>`

Convenience method for signing string messages.

```rust
let signature = wallet.sign_string_message("Hello, world!")?;
```

##### `verify_signature(&self, message: &[u8], signature_hex: &str) -> Result<bool, WalletError>`

Verifies a signature using the wallet's public key.

```rust
let message = b"Hello, world!";
let is_valid = wallet.verify_signature(message, &signature)?;
println!("Valid: {}", is_valid);
```

**Parameters:**

- `message` - The original message bytes
- `signature_hex` - The signature as a hex string

**Returns:**

- `Ok(true)` - If the signature is valid
- `Ok(false)` - If the signature is invalid
- `Err(WalletError)` - If verification fails due to format errors

##### `verify_string_signature(&self, message: &str, signature_hex: &str) -> Result<bool, WalletError>`

Convenience method for verifying signatures on string messages.

```rust
let is_valid = wallet.verify_string_signature("Hello, world!", &signature)?;
```

#### Getter Methods

##### `get_private_key_hex(&self) -> String`

Returns the private key as a hex string.

##### `get_public_key_hex(&self) -> String`

Returns the public key as a hex string (compressed format).

##### `get_private_key(&self) -> &SecretKey`

Returns a reference to the internal private key.

##### `get_public_key(&self) -> &PublicKey`

Returns a reference to the internal public key.

### Utility Functions

#### `validate_private_key_hex(hex_str: &str) -> Result<SecretKey, WalletError>`

Validates and parses a private key from a hex string.

```rust
use cli_wallet::wallet::validate_private_key_hex;

let private_key = validate_private_key_hex("0123...cdef")?;
```

**Requirements:**

- Exactly 64 hexadecimal characters
- Valid secp256k1 private key (not zero, within curve order)

#### `validate_public_key_hex(hex_str: &str) -> Result<PublicKey, WalletError>`

Validates and parses a public key from a hex string.

```rust
use cli_wallet::wallet::validate_public_key_hex;

let public_key = validate_public_key_hex("02a1b2...")?;
```

**Requirements:**

- 66 characters (compressed) or 130 characters (uncompressed)
- Valid secp256k1 public key point

#### `generate_address_from_public_key(public_key: &PublicKey) -> Result<String, WalletError>`

Generates a wallet address from any public key.

```rust
use cli_wallet::wallet::generate_address_from_public_key;

let address = generate_address_from_public_key(&public_key)?;
```

#### `validate_address_format(address: &str) -> Result<(), WalletError>`

Validates a wallet address format.

```rust
use cli_wallet::wallet::validate_address_format;

validate_address_format("1234567890abcdef...")?;
```

**Requirements:**

- Exactly 40 hexadecimal characters
- Valid hex encoding

#### `format_address(address: &str, with_prefix: bool) -> String`

Formats an address for display with optional "0x" prefix.

```rust
use cli_wallet::wallet::format_address;

let formatted = format_address("1234...", true); // "0x1234..."
```

## Crypto Module

The crypto module provides low-level cryptographic operations.

### Key Management (`crypto::keys`)

#### `generate_private_key() -> Result<SecretKey, WalletError>`

Generates a cryptographically secure random private key.

```rust
use cli_wallet::crypto::generate_private_key;

let private_key = generate_private_key()?;
```

#### `derive_public_key(private_key: &SecretKey) -> Result<PublicKey, WalletError>`

Derives a public key from a private key.

```rust
use cli_wallet::crypto::{generate_private_key, derive_public_key};

let private_key = generate_private_key()?;
let public_key = derive_public_key(&private_key)?;
```

#### `format_public_key(public_key: &PublicKey, compressed: bool) -> String`

Formats a public key as a hex string.

```rust
use cli_wallet::crypto::format_public_key;

let compressed = format_public_key(&public_key, true);    // 66 chars
let uncompressed = format_public_key(&public_key, false); // 130 chars
```

### Message Hashing (`crypto::hashing`)

#### `hash_message(message: &[u8]) -> Result<[u8; 32], WalletError>`

Hashes a message using SHA-256.

```rust
use cli_wallet::crypto::hash_message;

let hash = hash_message(b"Hello, world!")?;
```

### Signing Operations (`crypto::signing`)

#### `sign_message(message: &[u8], private_key: &SecretKey) -> Result<Signature, WalletError>`

Signs a message with a private key.

```rust
use cli_wallet::crypto::{sign_message, generate_private_key};

let private_key = generate_private_key()?;
let signature = sign_message(b"Hello, world!", &private_key)?;
```

#### `verify_signature(message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<bool, WalletError>`

Verifies a message signature.

```rust
use cli_wallet::crypto::verify_signature;

let is_valid = verify_signature(b"Hello, world!", &signature, &public_key)?;
```

#### `format_signature(signature: &Signature) -> String`

Formats a signature as a hex string.

```rust
use cli_wallet::crypto::format_signature;

let signature_hex = format_signature(&signature);
```

#### `parse_signature_hex(hex_str: &str) -> Result<Signature, WalletError>`

Parses a signature from a hex string.

```rust
use cli_wallet::crypto::parse_signature_hex;

let signature = parse_signature_hex("3045022100...")?;
```

## CLI Module

The CLI module provides command-line interface functionality.

### Command Execution

#### `execute_command(cli: Cli) -> Result<(), WalletError>`

Executes a parsed CLI command.

```rust
use cli_wallet::cli::{Cli, execute_command};
use clap::Parser;

let cli = Cli::parse();
execute_command(cli)?;
```

#### `display_help()`

Displays comprehensive help information.

```rust
use cli_wallet::cli::display_help;

display_help();
```

#### `display_error(error: &WalletError)`

Displays user-friendly error messages with suggestions.

```rust
use cli_wallet::cli::display_error;
use cli_wallet::WalletError;

let error = WalletError::invalid_input("Invalid key format");
display_error(&error);
```

### Command Structures

#### `Cli`

Main CLI structure parsed by clap.

```rust
pub struct Cli {
    pub command: Commands,
}
```

#### `Commands`

Available CLI commands.

```rust
pub enum Commands {
    Generate,
    Sign { message: String, private_key: String },
    Verify { message: String, signature: String, public_key: String },
}
```

## Error Handling

The library uses a comprehensive error handling system with the `WalletError` enum.

### Error Types

- **KeyGenerationError**: Issues with cryptographic key generation
- **SigningError**: Problems during message signing
- **VerificationError**: Signature verification failures
- **InvalidInput**: User input validation errors
- **CryptoError**: Low-level cryptographic operation failures
- **AddressError**: Address generation or validation issues

### Error Creation Utilities

```rust
use cli_wallet::WalletError;

let error = WalletError::invalid_input("Key must be 64 hex characters");
let error = WalletError::signing("Private key is invalid");
let error = WalletError::verification("Signature does not match");
```

### Error Conversion

The library automatically converts errors from external libraries:

```rust
impl From<secp256k1::Error> for WalletError { ... }
impl From<hex::FromHexError> for WalletError { ... }
```

## Usage Examples

### Basic Wallet Operations

```rust
use cli_wallet::{Wallet, WalletError};

fn main() -> Result<(), WalletError> {
    // Generate a new wallet
    let wallet = Wallet::new()?;

    // Get the keys and address
    let (private_key, public_key) = wallet.generate_keypair()?;
    let address = wallet.create_address()?;

    println!("Private Key: {}", private_key);
    println!("Public Key: {}", public_key);
    println!("Address: 0x{}", address);

    // Sign a message
    let message = "Hello, blockchain!";
    let signature = wallet.sign_string_message(message)?;
    println!("Signature: {}", signature);

    // Verify the signature
    let is_valid = wallet.verify_string_signature(message, &signature)?;
    println!("Signature valid: {}", is_valid);

    Ok(())
}
```

### Cross-Wallet Verification

```rust
use cli_wallet::{Wallet, WalletError};

fn main() -> Result<(), WalletError> {
    // Create two wallets
    let wallet1 = Wallet::new()?;
    let wallet2 = Wallet::new()?;

    // Sign a message with wallet1
    let message = "Cross-wallet test";
    let signature = wallet1.sign_string_message(message)?;

    // Try to verify with wallet2 (should fail)
    let is_valid = wallet2.verify_string_signature(message, &signature)?;
    println!("Cross-verification result: {}", is_valid); // false

    // Verify with correct wallet (should succeed)
    let is_valid = wallet1.verify_string_signature(message, &signature)?;
    println!("Self-verification result: {}", is_valid); // true

    Ok(())
}
```

### Using Crypto Functions Directly

```rust
use cli_wallet::crypto::{generate_private_key, derive_public_key, sign_message, verify_signature};
use cli_wallet::WalletError;

fn main() -> Result<(), WalletError> {
    // Generate keys
    let private_key = generate_private_key()?;
    let public_key = derive_public_key(&private_key)?;

    // Sign and verify
    let message = b"Direct crypto usage";
    let signature = sign_message(message, &private_key)?;
    let is_valid = verify_signature(message, &signature, &public_key)?;

    println!("Direct verification: {}", is_valid);

    Ok(())
}
```

### Error Handling Example

```rust
use cli_wallet::{Wallet, WalletError};

fn safe_wallet_operation() {
    match Wallet::new() {
        Ok(wallet) => {
            match wallet.sign_string_message("test") {
                Ok(signature) => println!("Signature: {}", signature),
                Err(e) => eprintln!("Signing failed: {}", e),
            }
        }
        Err(e) => eprintln!("Wallet creation failed: {}", e),
    }
}
```

## Security Considerations

### Key Management

- Private keys are only held in memory during operation
- Use secure random number generation for key creation
- Validate all cryptographic inputs
- Clear sensitive data when possible

### Input Validation

- All hex strings are validated for format and length
- Cryptographic parameters are checked for validity
- User inputs are sanitized and validated

### Error Handling

- Errors don't leak sensitive information
- Consistent timing to prevent side-channel attacks
- Clear error messages for debugging without security risks

## Thread Safety

The library is designed to be thread-safe:

- All functions are stateless or use immutable data
- No global mutable state
- Safe to use across multiple threads
- Cryptographic operations are deterministic

## Performance Considerations

- Key generation uses secure random number generation (may be slower)
- Signature operations are computationally intensive
- Public key operations are faster than private key operations
- Memory usage is minimal (keys are small)

## Compatibility

- **Rust Version**: Requires Rust 1.70 or later
- **Platforms**: Cross-platform (Windows, macOS, Linux)
- **Architecture**: Supports all architectures supported by Rust
- **Dependencies**: Uses well-maintained, audited cryptographic libraries

---

This API documentation covers all public interfaces of the CLI Wallet library. For implementation details, see the source code and inline documentation. For usage examples, see the examples directory.
