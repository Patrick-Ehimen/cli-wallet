// src/cli/mod.rs
pub mod commands;
pub mod parser;

// Re-export main CLI functionality
pub use commands::{display_error, display_help, execute_command};
pub use parser::{Cli, Commands};
