#!/bin/bash

# Basic CLI Wallet Usage Examples
# This script demonstrates the core functionality of the CLI wallet

set -e  # Exit on any error

echo "🔐 CLI Wallet - Basic Usage Examples"
echo "===================================="
echo

# Build the project first
echo "📦 Building the CLI wallet..."
cargo build --release
echo "✅ Build complete!"
echo

# Set the path to the binary
WALLET_BIN="./target/release/cli-wallet"

# Check if binary exists
if [ ! -f "$WALLET_BIN" ]; then
    echo "❌ Error: Binary not found at $WALLET_BIN"
    echo "Please run 'cargo build --release' first"
    exit 1
fi

echo "🔑 Example 1: Generate a new wallet"
echo "-----------------------------------"
echo "Command: $WALLET_BIN generate"
echo

# Generate a new wallet and capture the output
WALLET_OUTPUT=$($WALLET_BIN generate)
echo "$WALLET_OUTPUT"
echo

# Extract keys from the output (this is a simplified extraction for demo purposes)
# In a real script, you'd want more robust parsing
PRIVATE_KEY=$(echo "$WALLET_OUTPUT" | grep "Private Key:" | awk '{print $3}')
PUBLIC_KEY=$(echo "$WALLET_OUTPUT" | grep "Public Key:" | awk '{print $3}')

if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
    echo "❌ Error: Could not extract keys from wallet generation output"
    exit 1
fi

echo "📝 Example 2: Sign a message"
echo "-----------------------------"
MESSAGE="Hello from CLI Wallet!"
echo "Message: '$MESSAGE'"
echo "Command: $WALLET_BIN sign --message \"$MESSAGE\" --private-key $PRIVATE_KEY"
echo

# Sign the message
SIGN_OUTPUT=$($WALLET_BIN sign --message "$MESSAGE" --private-key "$PRIVATE_KEY")
echo "$SIGN_OUTPUT"
echo

# Extract signature from output
SIGNATURE=$(echo "$SIGN_OUTPUT" | grep "Signature:" | awk '{print $2}')

if [ -z "$SIGNATURE" ]; then
    echo "❌ Error: Could not extract signature from signing output"
    exit 1
fi

echo "✅ Example 3: Verify the signature"
echo "----------------------------------"
echo "Command: $WALLET_BIN verify --message \"$MESSAGE\" --signature $SIGNATURE --public-key $PUBLIC_KEY"
echo

# Verify the signature
VERIFY_OUTPUT=$($WALLET_BIN verify --message "$MESSAGE" --signature "$SIGNATURE" --public-key "$PUBLIC_KEY")
echo "$VERIFY_OUTPUT"
echo

echo "🎉 All examples completed successfully!"
echo
echo "💡 Key takeaways:"
echo "   • Private keys must be kept secret and secure"
echo "   • Public keys and addresses can be shared safely"
echo "   • Signatures prove ownership without revealing private keys"
echo "   • Always verify signatures before trusting signed messages"
echo
echo "🔒 Security reminder:"
echo "   This is a demonstration tool for learning purposes only."
echo "   Never use these keys for real cryptocurrency transactions!"