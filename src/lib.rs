// src/lib.rs
pub mod cli;
pub mod crypto;
pub mod error;
pub mod utils;
pub mod wallet;

// Re-export main types for easy access
pub use errors::{WalletError, WalletResult};
// pub use wallet::Wallet;
