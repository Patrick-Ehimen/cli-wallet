use cli_wallet::cli::{Cli, display_error, display_help, execute_command};
use cli_wallet::error::WalletError;
use std::env;
use std::process;

fn main() {
    // Set up global error handling with panic hook
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("❌ Fatal Error: The application encountered an unexpected error and must exit.");
        eprintln!("   {}", panic_info);
        eprintln!();
        eprintln!("💡 This is likely a bug. Please report this issue with the following details:");
        eprintln!("   - Command you were running");
        eprintln!("   - Input parameters");
        eprintln!("   - Error message above");
        process::exit(2);
    }));

    // Handle the case where no arguments are provided
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        display_help();
        return;
    }

    // Parse command line arguments with proper error handling
    let cli = match Cli::try_parse_args() {
        Ok(cli) => cli,
        Err(clap_error) => {
            // Handle clap parsing errors gracefully
            match clap_error.kind() {
                clap::error::ErrorKind::DisplayHelp => {
                    print!("{}", clap_error);
                    return;
                }
                clap::error::ErrorKind::DisplayVersion => {
                    print!("{}", clap_error);
                    return;
                }
                _ => {
                    eprintln!("❌ Command line error: {}", clap_error);
                    eprintln!();
                    eprintln!("💡 For help, run: cli-wallet --help");
                    process::exit(1);
                }
            }
        }
    };

    // Execute the command with comprehensive error handling
    match execute_command(cli) {
        Ok(()) => {
            // Command executed successfully - exit with success code
            process::exit(0);
        }
        Err(error) => {
            // Display user-friendly error message
            display_error(&error);

            // Exit with appropriate error code based on error type
            let exit_code = match error {
                WalletError::InvalidInput(_) => 1,       // User input error
                WalletError::KeyGenerationError(_) => 2, // Crypto/system error
                WalletError::SigningError(_) => 2,       // Crypto/system error
                WalletError::VerificationError(_) => 2,  // Crypto/system error
                WalletError::AddressError(_) => 2,       // Crypto/system error
                WalletError::CryptoError(_) => 2,        // Crypto/system error
            };

            process::exit(exit_code);
        }
    }
}
