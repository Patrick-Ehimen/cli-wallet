use clap::Parser;

#[derive(Parser)]
#[command(name = "cli-wallet")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand)]
pub enum Commands {
    Verify {
        #[arg(short, long)]
        message: String,
        #[arg(short, long)]
        signature: String,
        #[arg(short = 'k', long = "public-key")]
        public_key: String,
    },
}

fn main() {
    let args = vec![
        "cli-wallet",
        "verify",
        "--message",
        "hello world",
        "--signature",
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "--public-key",
        "021234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
    ];

    let cli = Cli::try_parse_from(args).unwrap();

    match &cli.command {
        Commands::Verify {
            message,
            signature,
            public_key,
        } => {
            println!("Message: '{}' (len: {})", message, message.len());
            println!("Signature: '{}' (len: {})", signature, signature.len());
            println!("Public key: '{}' (len: {})", public_key, public_key.len());
        }
    }
}
