# CLI Wallet Examples

This directory contains example scripts demonstrating how to use the CLI wallet application.

## Available Examples

### 1. Basic Usage (`basic_usage.sh`)

Demonstrates the fundamental operations of the CLI wallet:

- Generating a new wallet (private key, public key, and address)
- Signing a message with the private key
- Verifying the signature with the public key

**Run the example:**

```bash
chmod +x examples/basic_usage.sh
./examples/basic_usage.sh
```

**What you'll learn:**

- How to generate a secure wallet
- How to sign messages for authentication
- How to verify signatures to confirm authenticity
- Basic security principles

### 2. Advanced Usage (`advanced_usage.sh`)

Demonstrates more complex scenarios and edge cases:

- Generating multiple unique wallets
- Signing multiple messages with the same key
- Batch signature verification
- Error handling and validation
- Cross-verification security testing

**Run the example:**

```bash
chmod +x examples/advanced_usage.sh
./examples/advanced_usage.sh
```

**What you'll learn:**

- How wallets generate unique addresses
- How signatures work with different messages
- How the application handles errors
- Why signatures can't be used across different wallets
- Security properties of the cryptographic system

## Prerequisites

Before running the examples, make sure you have:

1. **Rust installed** (1.70 or later)
2. **The project built**: Run `cargo build --release` in the project root
3. **Execute permissions**: Run `chmod +x examples/*.sh` to make scripts executable

## Example Output

### Basic Usage Example Output

```
🔐 CLI Wallet - Basic Usage Examples
====================================

📦 Building the CLI wallet...
✅ Build complete!

🔑 Example 1: Generate a new wallet
-----------------------------------
Command: ./target/release/cli-wallet generate

🔑 New wallet generated successfully!

Private Key: a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab
Public Key:  02b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abc
Address:     2b3c4d5e6f7890abcdef1234567890abcdef1234

⚠️  IMPORTANT: Keep your private key secure and never share it!
💡 Your address can be shared publicly to receive transactions.

📝 Example 2: Sign a message
-----------------------------
Message: 'Hello from CLI Wallet!'
Command: ./target/release/cli-wallet sign --message "Hello from CLI Wallet!" --private-key a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab

✅ Message signed successfully!

Message:   Hello from CLI Wallet!
Signature: 304502210098a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a022019b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab

💡 Share this signature along with your public key to prove message authenticity.

✅ Example 3: Verify the signature
----------------------------------
Command: ./target/release/cli-wallet verify --message "Hello from CLI Wallet!" --signature 304502210098a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a022019b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab --public-key 02b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abc

✅ Signature verification successful!

Message:    Hello from CLI Wallet!
Public Key: 02b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abc
Signature:  304502210098a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a022019b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab
Result:     VALID ✅

💡 This signature was created by the holder of the corresponding private key.

🎉 All examples completed successfully!
```

## Security Notes

⚠️ **Important Security Reminders:**

1. **Educational Purpose Only**: These examples are for learning cryptographic concepts
2. **Never Use Real Keys**: Don't use generated keys for actual cryptocurrency
3. **Private Key Security**: In real applications, never log or display private keys
4. **Secure Storage**: Private keys should be encrypted and stored securely
5. **Network Security**: This tool works offline - no network transmission of keys

## Troubleshooting

### Common Issues

**"Binary not found" error:**

```bash
❌ Error: Binary not found at ./target/release/cli-wallet
```

**Solution:** Run `cargo build --release` in the project root directory.

**"Permission denied" error:**

```bash
bash: ./examples/basic_usage.sh: Permission denied
```

**Solution:** Make the script executable with `chmod +x examples/basic_usage.sh`.

**Build errors:**

```bash
error: could not compile `cli-wallet`
```

**Solution:** Ensure you have Rust 1.70+ installed and all dependencies are available.

### Getting Help

If you encounter issues:

1. Check that you're in the project root directory
2. Ensure Rust and Cargo are properly installed
3. Try running `cargo clean` and then `cargo build --release`
4. Check the main README.md for additional troubleshooting steps

## Learning Resources

After running these examples, you might want to learn more about:

- **Elliptic Curve Cryptography**: Understanding the math behind secp256k1
- **Digital Signatures**: How ECDSA signatures provide authentication
- **Cryptocurrency Wallets**: How real wallets implement these concepts
- **Rust Cryptography**: Using crypto libraries safely in Rust

## Next Steps

Once you understand these examples:

1. **Explore the source code** in `src/` to see how it's implemented
2. **Run the tests** with `cargo test` to see comprehensive test coverage
3. **Modify the examples** to experiment with different scenarios
4. **Read the API documentation** to understand the library interface

Remember: This is a learning tool. For production cryptocurrency applications, use established, audited libraries and follow security best practices!
