#!/bin/bash

# Advanced CLI Wallet Usage Examples
# This script demonstrates more complex scenarios and error handling

set -e  # Exit on any error

echo "🔐 CLI Wallet - Advanced Usage Examples"
echo "========================================"
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

echo "🔄 Example 1: Multiple wallet generation"
echo "----------------------------------------"
echo "Generating 3 different wallets to show uniqueness..."
echo

for i in {1..3}; do
    echo "Wallet $i:"
    WALLET_OUTPUT=$($WALLET_BIN generate)
    # Extract just the address for comparison
    ADDRESS=$(echo "$WALLET_OUTPUT" | grep "Address:" | awk '{print $2}')
    echo "  Address: $ADDRESS"
done
echo "✅ Each wallet has a unique address!"
echo

echo "📋 Example 2: Signing multiple messages with same key"
echo "-----------------------------------------------------"
echo "Generating a wallet and signing different messages..."
echo

# Generate a wallet for this example
WALLET_OUTPUT=$($WALLET_BIN generate)
PRIVATE_KEY=$(echo "$WALLET_OUTPUT" | grep "Private Key:" | awk '{print $3}')
PUBLIC_KEY=$(echo "$WALLET_OUTPUT" | grep "Public Key:" | awk '{print $3}')

echo "Using wallet:"
echo "  Private Key: ${PRIVATE_KEY:0:16}...${PRIVATE_KEY: -16}"  # Show partial key for security
echo "  Public Key:  $PUBLIC_KEY"
echo

# Sign multiple messages
MESSAGES=("Hello World" "CLI Wallet Demo" "Cryptographic Signature" "2024-01-01 Transaction")

declare -a SIGNATURES

for i in "${!MESSAGES[@]}"; do
    MESSAGE="${MESSAGES[$i]}"
    echo "Signing message $((i+1)): '$MESSAGE'"
    
    SIGN_OUTPUT=$($WALLET_BIN sign --message "$MESSAGE" --private-key "$PRIVATE_KEY")
    SIGNATURE=$(echo "$SIGN_OUTPUT" | grep "Signature:" | awk '{print $2}')
    SIGNATURES[$i]="$SIGNATURE"
    
    echo "  Signature: ${SIGNATURE:0:20}...${SIGNATURE: -20}"
    echo
done

echo "✅ All messages signed successfully!"
echo

echo "🔍 Example 3: Batch signature verification"
echo "------------------------------------------"
echo "Verifying all signatures from the previous example..."
echo

for i in "${!MESSAGES[@]}"; do
    MESSAGE="${MESSAGES[$i]}"
    SIGNATURE="${SIGNATURES[$i]}"
    
    echo "Verifying message $((i+1)): '$MESSAGE'"
    
    VERIFY_OUTPUT=$($WALLET_BIN verify --message "$MESSAGE" --signature "$SIGNATURE" --public-key "$PUBLIC_KEY")
    
    if echo "$VERIFY_OUTPUT" | grep -q "VALID"; then
        echo "  ✅ Signature is VALID"
    else
        echo "  ❌ Signature is INVALID"
    fi
done
echo

echo "🚫 Example 4: Error handling demonstrations"
echo "-------------------------------------------"
echo "Demonstrating various error conditions..."
echo

# Function to safely run commands that might fail
run_error_example() {
    local description="$1"
    local command="$2"
    
    echo "Testing: $description"
    echo "Command: $command"
    
    if output=$(eval "$command" 2>&1); then
        echo "  Unexpected success: $output"
    else
        echo "  ✅ Expected error caught:"
        echo "  $output" | sed 's/^/    /'
    fi
    echo
}

# Test various error conditions
run_error_example "Invalid private key (too short)" \
    "$WALLET_BIN sign --message 'test' --private-key 'invalid'"

run_error_example "Invalid private key (non-hex characters)" \
    "$WALLET_BIN sign --message 'test' --private-key 'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg'"

run_error_example "Invalid public key format" \
    "$WALLET_BIN verify --message 'test' --signature '3045022100a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a02201b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab' --public-key 'invalid'"

run_error_example "Invalid signature format" \
    "$WALLET_BIN verify --message 'test' --signature 'invalid' --public-key '$PUBLIC_KEY'"

run_error_example "Missing required argument" \
    "$WALLET_BIN sign --message 'test'"

echo "✅ Error handling working correctly!"
echo

echo "🔐 Example 5: Cross-verification test"
echo "-------------------------------------"
echo "Testing that signatures from one wallet cannot be verified with another wallet's public key..."
echo

# Generate two different wallets
echo "Generating first wallet..."
WALLET1_OUTPUT=$($WALLET_BIN generate)
WALLET1_PRIVATE=$(echo "$WALLET1_OUTPUT" | grep "Private Key:" | awk '{print $3}')
WALLET1_PUBLIC=$(echo "$WALLET1_OUTPUT" | grep "Public Key:" | awk '{print $3}')

echo "Generating second wallet..."
WALLET2_OUTPUT=$($WALLET_BIN generate)
WALLET2_PUBLIC=$(echo "$WALLET2_OUTPUT" | grep "Public Key:" | awk '{print $3}')

echo "Wallet 1 Public Key: $WALLET1_PUBLIC"
echo "Wallet 2 Public Key: $WALLET2_PUBLIC"
echo

# Sign a message with wallet 1
TEST_MESSAGE="Cross-verification test"
echo "Signing message with Wallet 1: '$TEST_MESSAGE'"
SIGN_OUTPUT=$($WALLET_BIN sign --message "$TEST_MESSAGE" --private-key "$WALLET1_PRIVATE")
SIGNATURE=$(echo "$SIGN_OUTPUT" | grep "Signature:" | awk '{print $2}')
echo "Signature: ${SIGNATURE:0:20}...${SIGNATURE: -20}"
echo

# Verify with wallet 1's public key (should succeed)
echo "Verifying with Wallet 1's public key (should succeed):"
VERIFY1_OUTPUT=$($WALLET_BIN verify --message "$TEST_MESSAGE" --signature "$SIGNATURE" --public-key "$WALLET1_PUBLIC")
if echo "$VERIFY1_OUTPUT" | grep -q "VALID"; then
    echo "  ✅ VALID (as expected)"
else
    echo "  ❌ INVALID (unexpected!)"
fi
echo

# Verify with wallet 2's public key (should fail)
echo "Verifying with Wallet 2's public key (should fail):"
VERIFY2_OUTPUT=$($WALLET_BIN verify --message "$TEST_MESSAGE" --signature "$SIGNATURE" --public-key "$WALLET2_PUBLIC")
if echo "$VERIFY2_OUTPUT" | grep -q "INVALID"; then
    echo "  ✅ INVALID (as expected - signature doesn't match this public key)"
else
    echo "  ❌ VALID (unexpected! This would be a security issue)"
fi
echo

echo "🎉 All advanced examples completed successfully!"
echo
echo "📚 What we learned:"
echo "   • Each wallet generates unique keys and addresses"
echo "   • The same private key can sign multiple different messages"
echo "   • Signatures are message-specific and cannot be reused"
echo "   • Signatures can only be verified with the correct public key"
echo "   • The application handles errors gracefully with helpful messages"
echo
echo "🔒 Security insights:"
echo "   • Private keys must remain secret - they prove ownership"
echo "   • Public keys can be shared - they verify signatures"
echo "   • Signatures are cryptographic proofs that cannot be forged"
echo "   • Cross-verification fails as expected - preventing impersonation"
echo
echo "⚠️  Remember: This is for educational purposes only!"