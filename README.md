# CLI Wallet

A command-line cryptocurrency wallet application built in Rust that provides fundamental wallet operations using the secp256k1 elliptic curve cryptography (commonly used in Bitcoin and Ethereum).

## Features

- **Key Generation**: Generate secure secp256k1 private/public key pairs
- **Address Creation**: Create wallet addresses from public keys using SHA-256 hashing
- **Message Signing**: Sign messages with your private key for authentication
- **Signature Verification**: Verify message signatures to confirm authenticity
- **User-Friendly CLI**: Intuitive command-line interface with comprehensive help

## Installation

### Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)

### Building from Source

```bash
git clone <repository-url>
cd cli-wallet
cargo build --release
```

The compiled binary will be available at `target/release/cli-wallet`.

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test wallet::tests
```

## Usage

### Basic Commands

The CLI wallet supports four main operations:

#### 1. Generate a New Wallet

Generate a new private/public key pair and wallet address:

```bash
cli-wallet generate
```

**Example Output:**

```
🔑 New wallet generated successfully!

Private Key: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Public Key:  02a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a
Address:     1a2b3c4d5e6f7890abcdef1234567890abcdef12

⚠️  IMPORTANT: Keep your private key secure and never share it!
💡 Your address can be shared publicly to receive transactions.
```

#### 2. Sign a Message

Sign a message using your private key:

```bash
cli-wallet sign --message "Hello, world!" --private-key <your-private-key>
```

**Example:**

```bash
cli-wallet sign --message "Hello, world!" --private-key e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Example Output:**

```
✅ Message signed successfully!

Message:   Hello, world!
Signature: 3045022100a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a02201b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab

💡 Share this signature along with your public key to prove message authenticity.
```

#### 3. Verify a Signature

Verify that a signature is valid for a given message and public key:

```bash
cli-wallet verify --message "Hello, world!" --signature <signature> --public-key <public-key>
```

**Example:**

```bash
cli-wallet verify \
  --message "Hello, world!" \
  --signature 3045022100a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a02201b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab \
  --public-key 02a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a
```

**Example Output:**

```
✅ Signature verification successful!

Message:    Hello, world!
Public Key: 02a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a
Signature:  3045022100a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a02201b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab
Result:     VALID ✅

💡 This signature was created by the holder of the corresponding private key.
```

#### 4. Get Help

Display help information:

```bash
cli-wallet --help
cli-wallet <command> --help
```

### Complete Workflow Example

Here's a complete example showing how to generate a wallet, sign a message, and verify the signature:

```bash
# 1. Generate a new wallet
$ cli-wallet generate
🔑 New wallet generated successfully!
Private Key: a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab
Public Key:  02b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abc
Address:     2b3c4d5e6f7890abcdef1234567890abcdef1234

# 2. Sign a message (use the private key from step 1)
$ cli-wallet sign --message "I own this wallet" --private-key a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab
✅ Message signed successfully!
Signature: 304502210098a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a022019b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab

# 3. Verify the signature (use public key and signature from above)
$ cli-wallet verify \
  --message "I own this wallet" \
  --signature 304502210098a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a022019b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab \
  --public-key 02b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abc
✅ Signature verification successful!
Result: VALID ✅
```

## Command Reference

### `generate`

Generate a new wallet with private key, public key, and address.

**Usage:** `cli-wallet generate`

**Options:** None

**Output:** Displays the generated private key, public key, and wallet address.

### `sign`

Sign a message using a private key.

**Usage:** `cli-wallet sign --message <MESSAGE> --private-key <PRIVATE_KEY>`

**Options:**

- `--message, -m <MESSAGE>`: The message to sign (required)
- `--private-key, -k <PRIVATE_KEY>`: The private key in hex format (64 characters, required)

**Output:** Displays the message and its signature in hex format.

### `verify`

Verify a message signature using a public key.

**Usage:** `cli-wallet verify --message <MESSAGE> --signature <SIGNATURE> --public-key <PUBLIC_KEY>`

**Options:**

- `--message, -m <MESSAGE>`: The original message that was signed (required)
- `--signature, -s <SIGNATURE>`: The signature in hex format (required)
- `--public-key, -p <PUBLIC_KEY>`: The public key in hex format (66 or 130 characters, required)

**Output:** Displays verification result (VALID or INVALID) with details.

### Global Options

- `--help, -h`: Show help information
- `--version, -V`: Show version information

## Security Considerations

### Private Key Security

- **Never share your private key**: Anyone with access to your private key can sign messages on your behalf
- **Store securely**: Keep private keys in secure, encrypted storage
- **Use strong randomness**: This application uses cryptographically secure random number generation
- **No persistent storage**: Private keys are only held in memory during operation

### Best Practices

1. **Generate keys offline**: For maximum security, generate keys on an air-gapped machine
2. **Verify signatures**: Always verify signatures before trusting signed messages
3. **Use unique keys**: Generate separate key pairs for different purposes
4. **Regular backups**: Securely backup your private keys (encrypted)
5. **Test first**: Test with small amounts or test networks before using with valuable assets

### Cryptographic Details

- **Elliptic Curve**: secp256k1 (same as Bitcoin and Ethereum)
- **Hashing Algorithm**: SHA-256 for message hashing and address generation
- **Signature Scheme**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Key Format**: Private keys are 32 bytes (64 hex chars), public keys are 33 bytes compressed (66 hex chars)
- **Address Format**: 20 bytes (40 hex chars) derived from SHA-256 hash of public key

### Known Limitations

- **Educational Purpose**: This is a simplified wallet for learning - not suitable for production use with real cryptocurrency
- **No Key Storage**: Keys are not persistently stored - you must manage them externally
- **Basic Address Format**: Uses simplified address generation (not Bitcoin/Ethereum compatible)
- **No Network Features**: This is an offline tool - no blockchain interaction

## Error Handling

The application provides clear error messages for common issues:

### Invalid Input Errors

```bash
❌ Invalid Input: Private key hex string must be 64 characters, got 62
💡 Private keys must be exactly 64 hexadecimal characters (32 bytes)
```

### Cryptographic Errors

```bash
❌ Cryptographic Error: Invalid private key format
💡 Ensure your private key is a valid secp256k1 private key
```

### Verification Errors

```bash
❌ Verification Error: Signature does not match message and public key
💡 Check that the signature, message, and public key are all correct
```

## Development

### Project Structure

```
src/
├── main.rs           # Application entry point
├── lib.rs            # Library exports
├── cli/              # Command-line interface
│   ├── mod.rs        # CLI module exports
│   ├── commands.rs   # Command handlers
│   └── parser.rs     # Argument parsing
├── crypto/           # Cryptographic operations
│   ├── mod.rs        # Crypto module exports
│   ├── keys.rs       # Key generation and formatting
│   ├── signing.rs    # Message signing and verification
│   └── hashing.rs    # SHA-256 hashing utilities
├── wallet.rs         # Core wallet functionality
├── error.rs          # Error types and handling
└── utils/            # Utility functions
    ├── mod.rs        # Utils module exports
    ├── formatting.rs # Display formatting
    └── validation.rs # Input validation
```

### Dependencies

- **secp256k1**: Elliptic curve cryptography
- **sha2**: SHA-256 hashing
- **rand**: Secure random number generation
- **clap**: Command-line argument parsing
- **hex**: Hexadecimal encoding/decoding

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run `cargo test` to ensure all tests pass
6. Run `cargo fmt` to format code
7. Run `cargo clippy` to check for issues
8. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided for educational purposes only. It is not intended for use with real cryptocurrency or in production environments. The authors are not responsible for any loss of funds or security breaches resulting from the use of this software.
