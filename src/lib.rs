// src/lib.rs
pub mod cli;
pub mod crypto;
pub mod debug;
pub mod error;
pub mod utils;
pub mod wallet;

// Re-export main types for easy access
pub use error::{WalletError, WalletResult};
pub use wallet::Wallet;
