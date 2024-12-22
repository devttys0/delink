use thiserror::Error;

/// Report error status
#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid encrypted data")]
    Input,
    #[error("invalid decrypted data")]
    Output,
}

/// Each decryption function must conform to this type
pub type DecryptorFunction = fn(&[u8]) -> Result<Vec<u8>, DecryptError>;
