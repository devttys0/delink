use log::{error, info, trace};
use thiserror::Error;
mod aes;
mod common;
mod dap1610;
mod decryptor;
mod dlk;
mod encimg;
mod encrpted;
mod mh01;
mod openssl;
mod sha1_hmac;
mod shrs;
mod tlv;

#[derive(Error, Debug)]
pub enum ApplicationError {
    #[error("usage error")]
    Usage,
    #[error("decryption failure")]
    DecryptFail,
    #[error("failed to write data to disk")]
    WriteFail,
    #[error("failed to read data from disk")]
    ReadFail,
    #[error("unknown error")]
    Unknown,
}

fn main() -> Result<(), ApplicationError> {
    const REQUIRED_CMD_ARGS_LEN: usize = 3;

    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    // Get command line arguments
    let cmdline: Vec<String> = std::env::args().collect();

    // Check usage
    if cmdline.len() == REQUIRED_CMD_ARGS_LEN {
        // Expected usage: <input file> <output file>
        let input_file_name = cmdline[1].clone();
        let output_file_name = cmdline[2].clone();

        // Read the contents of the input file
        match std::fs::read(&input_file_name) {
            Err(e) => {
                error!("Failed to read input file '{}': {}", input_file_name, e);
                Err(ApplicationError::ReadFail)
            }
            Ok(file_data) => {
                trace!("Attempting to decrypt data from: {}", input_file_name);

                // Try all decryption methods
                if let Ok(decrypted_data) = decryptor::decrypt(&file_data) {
                    info!("Decryption successful!");
                    if write_decrypted_data(&output_file_name, &decrypted_data) {
                        Ok(())
                    } else {
                        Err(ApplicationError::WriteFail)
                    }
                } else {
                    error!("All decryption attempts have failed :(");
                    Err(ApplicationError::DecryptFail)
                }
            }
        }
    } else {
        error!(
            "Usage: {} <path to encrypted firmware> <output file>",
            cmdline[0]
        );
        Err(ApplicationError::Usage)
    }
}

fn write_decrypted_data(file_name: &str, decrypted_data: &[u8]) -> bool {
    // Write decrypted contents to the output file
    match std::fs::write(file_name, decrypted_data) {
        Err(e) => {
            error!("Failed to save decrypted data to '{}': {}", file_name, e);
            false
        }
        Ok(_) => {
            info!("Decrypted data saved to: {}", file_name);
            true
        }
    }
}
