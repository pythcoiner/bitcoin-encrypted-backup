#[cfg(feature = "miniscript_12_0")]
pub use mscript_12_0 as miniscript;
#[cfg(feature = "miniscript_12_3_5")]
pub use mscript_12_3_5 as miniscript;

use clap::Parser;
use clap::Subcommand;

use bitcoin_encrypted_backup::Decrypted;
use bitcoin_encrypted_backup::EncryptedBackup;
use miniscript::descriptor::DescriptorKeyParseError;
use miniscript::DescriptorPublicKey;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug)]
pub enum CliError {
    CantConvertToXpub(DescriptorKeyParseError),
    EmptyDescriptor,
    CwdError(std::io::Error),
    OpenError(std::io::Error),
    WriteError(std::io::Error),
    ReadError(std::io::Error),
    FailedToDecrypt(bitcoin_encrypted_backup::Error),
    Content,
    NoKeys,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::CantConvertToXpub(err) => {
                write!(f, "Can't  convert to master public key: {err:?}")
            }
            CliError::EmptyDescriptor => write!(f, "Empty descriptor"),
            CliError::CwdError(err) => write!(f, "Cant find current working directiory: {err:?}"),
            CliError::OpenError(err) => write!(f, "Cannot open file: {err:?}"),
            CliError::WriteError(err) => write!(f, "Cannot write file: {err:?}"),
            CliError::ReadError(err) => write!(f, "Cannot read file: {err:?}"),
            CliError::FailedToDecrypt(err) => write!(f, "Cannot decrypt: {err:?}"),
            CliError::Content => write!(f, "Decryption succeed but content is not a descriptor"),
            CliError::NoKeys => write!(f, "No decryption key found"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Decrypt an encrypted descriptor with a given xpub
    Decrypt {
        /// Input file to be decrypted
        #[arg(short, long)]
        file: Option<String>,

        /// The key containing a xpub
        #[arg(short, long)]
        key: Option<String>,

        /// Optional decrypted descriptor
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Handle the specific subcommand
    match &cli.command {
        Commands::Decrypt { file, key, output } => {
            let input_path = match file {
                Some(path) => {
                    let mut descriptor_path = PathBuf::new();
                    descriptor_path.push(path);
                    descriptor_path
                }
                None => {
                    let mut descriptor_path = env::current_dir().map_err(CliError::CwdError)?;
                    descriptor_path.push("descriptor.txt");
                    descriptor_path
                }
            };

            let output_path = match output {
                Some(path) => {
                    let mut output_path = PathBuf::new();
                    output_path.push(path);
                    output_path
                }
                None => {
                    let mut output_path = env::current_dir().map_err(CliError::CwdError)?;
                    output_path.push("descriptor.txt");
                    output_path
                }
            };

            let key_path = match key {
                Some(path) => {
                    let mut xpub_path = PathBuf::new();
                    xpub_path.push(path);
                    xpub_path
                }
                None => {
                    let mut xpub_path = env::current_dir().map_err(CliError::CwdError)?;
                    xpub_path.push("xpub.txt");
                    xpub_path
                }
            };
            let key = if let Ok(k) = fs::read_to_string(key_path) {
                DescriptorPublicKey::from_str(k.trim()).ok()
            } else {
                None
            };

            let data = fs::read(&input_path).map_err(CliError::ReadError)?;

            let backup = EncryptedBackup::new()
                .set_encrypted_payload(&data)
                .map_err(CliError::FailedToDecrypt)?;

            #[cfg(feature = "devices")]
            let mut keys = {
                let deriv_paths = backup.get_derivation_paths();
                bitcoin_encrypted_backup::signing_devices::collect_xpubs(deriv_paths).await
            };

            #[cfg(not(feature = "devices"))]
            let mut keys = vec![];

            if let Some(k) = key {
                keys.push(k);
            }

            if keys.is_empty() {
                return Err(CliError::NoKeys);
            }

            let (pks, _) =
                bitcoin_encrypted_backup::descriptor::dpks_to_derivation_keys_paths(&keys);

            let decrypted = backup
                .set_keys(pks)
                .decrypt()
                .map_err(CliError::FailedToDecrypt)?;

            let descriptor = if let Decrypted::Descriptor(descr) = decrypted {
                descr.to_string()
            } else {
                return Err(CliError::Content);
            };
            fs::write(&output_path, &descriptor).map_err(CliError::WriteError)?;
            println!("descriptor written to {output_path:?}");
        }
    }
    Ok(())
}
