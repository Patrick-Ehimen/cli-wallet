use clap::{Parser, Subcommand};

/// Simple CLI Wallet - A command-line cryptocurrency wallet
#[derive(Parser)]
#[command(name = "cli-wallet")]
#[command(about = "A simple command-line cryptocurrency wallet using secp256k1")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new key pair and wallet address
    Generate,

    /// Sign a message with a private key
    Sign {
        /// The message to sign
        #[arg(short, long)]
        message: String,

        /// The private key in hex format
        #[arg(short = 'k', long = "private-key")]
        private_key: String,
    },

    /// Verify a message signature
    Verify {
        /// The original message
        #[arg(short, long)]
        message: String,

        /// The signature in hex format
        #[arg(short, long)]
        signature: String,

        /// The public key in hex format
        #[arg(short = 'k', long = "public-key")]
        public_key: String,
    },
}

impl Cli {
    /// Parse command line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Try to parse command line arguments, returning clap errors for handling
    pub fn try_parse_args() -> Result<Self, clap::Error> {
        Self::try_parse()
    }

    /// Validate the parsed arguments
    pub fn validate(&self) -> Result<(), String> {
        match &self.command {
            Commands::Generate => Ok(()),
            Commands::Sign {
                message,
                private_key,
            } => {
                if message.is_empty() {
                    return Err("Message cannot be empty".to_string());
                }
                if private_key.is_empty() {
                    return Err("Private key cannot be empty".to_string());
                }
                // Basic hex validation - should be 64 characters (32 bytes * 2)
                if private_key.len() != 64 {
                    return Err("Private key must be 64 hex characters (32 bytes)".to_string());
                }
                if !private_key.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("Private key must contain only hex characters".to_string());
                }
                Ok(())
            }
            Commands::Verify {
                message,
                signature,
                public_key,
            } => {
                if message.is_empty() {
                    return Err("Message cannot be empty".to_string());
                }
                if signature.is_empty() {
                    return Err("Signature cannot be empty".to_string());
                }
                if public_key.is_empty() {
                    return Err("Public key cannot be empty".to_string());
                }
                // Basic hex validation for signature (should be 128 characters for r+s components)
                if signature.len() != 128 {
                    return Err("Signature must be 128 hex characters (64 bytes)".to_string());
                }
                if !signature.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("Signature must contain only hex characters".to_string());
                }
                // Basic hex validation for public key (should be 66 characters for compressed key)
                if public_key.len() != 66 {
                    return Err(
                        "Public key must be 66 hex characters (33 bytes compressed)".to_string()
                    );
                }
                if !public_key.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("Public key must contain only hex characters".to_string());
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_generate_command_parsing() {
        let args = vec!["cli-wallet", "generate"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli.command {
            Commands::Generate => assert!(true),
            _ => panic!("Expected Generate command"),
        }

        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_sign_command_parsing() {
        let args = vec![
            "cli-wallet",
            "sign",
            "--message",
            "hello world",
            "--private-key",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match &cli.command {
            Commands::Sign {
                message,
                private_key,
            } => {
                assert_eq!(message, "hello world");
                assert_eq!(
                    private_key,
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                );
            }
            _ => panic!("Expected Sign command"),
        }

        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_verify_command_parsing() {
        let args = vec![
            "cli-wallet",
            "verify",
            "--message",
            "hello world",
            "--signature",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "--public-key",
            "021234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match &cli.command {
            Commands::Verify {
                message,
                signature,
                public_key,
            } => {
                assert_eq!(message, "hello world");
                assert_eq!(
                    signature,
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                );
                assert_eq!(
                    public_key,
                    "021234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                );
            }
            _ => panic!("Expected Verify command"),
        }

        assert!(cli.validate().is_ok());
    }

    #[test]
    fn test_sign_command_validation_empty_message() {
        let args = vec![
            "cli-wallet",
            "sign",
            "--message",
            "",
            "--private-key",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        assert!(cli.validate().is_err());
        assert_eq!(cli.validate().unwrap_err(), "Message cannot be empty");
    }

    #[test]
    fn test_sign_command_validation_invalid_private_key_length() {
        let args = vec![
            "cli-wallet",
            "sign",
            "--message",
            "hello",
            "--private-key",
            "123", // Too short
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        assert!(cli.validate().is_err());
        assert_eq!(
            cli.validate().unwrap_err(),
            "Private key must be 64 hex characters (32 bytes)"
        );
    }

    #[test]
    fn test_sign_command_validation_invalid_private_key_chars() {
        let args = vec![
            "cli-wallet",
            "sign",
            "--message",
            "hello",
            "--private-key",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", // Invalid hex chars
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        assert!(cli.validate().is_err());
        assert_eq!(
            cli.validate().unwrap_err(),
            "Private key must contain only hex characters"
        );
    }

    #[test]
    fn test_verify_command_validation_invalid_signature_length() {
        let args = vec![
            "cli-wallet",
            "verify",
            "--message",
            "hello",
            "--signature",
            "123", // Too short
            "--public-key",
            "021234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        assert!(cli.validate().is_err());
        assert_eq!(
            cli.validate().unwrap_err(),
            "Signature must be 128 hex characters (64 bytes)"
        );
    }

    #[test]
    fn test_verify_command_validation_invalid_public_key_length() {
        let args = vec![
            "cli-wallet",
            "verify",
            "--message",
            "hello",
            "--signature",
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "--public-key",
            "123", // Too short
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        assert!(cli.validate().is_err());
        assert_eq!(
            cli.validate().unwrap_err(),
            "Public key must be 66 hex characters (33 bytes compressed)"
        );
    }
}
