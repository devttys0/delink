use crate::common::DecryptError;
use crate::openssl::{aes_256_cbc_decrypt, MessageDigest};
use log::debug;

/// Decrypt DAP-1610 B1 firmware
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Password to decrypt DAP-1610 B1 firmware
    const PASSWORD: &str = "2c3b6fa78bd60b41bb0796fef4b058b0";

    // Decrypted data is expected to be a TAR archive
    const MAGIC: &[u8] = b"ustar";
    const MAGIC_START: usize = 0x101;
    const MAGIC_END: usize = MAGIC_START + MAGIC.len();

    if let Ok(decrypted_data) =
        aes_256_cbc_decrypt(encrypted_data, PASSWORD, MessageDigest::SHA256, None)
    {
        if let Some(magic) = decrypted_data.get(MAGIC_START..MAGIC_END) {
            if magic == MAGIC {
                return Ok(decrypted_data);
            } else {
                debug!("Decrypted magic bytes do not match");
                return Err(DecryptError::Output);
            }
        } else {
            debug!("Failed to read decrypted magic bytes");
            return Err(DecryptError::Output);
        }
    }

    debug!("Failed to decrypt with known key");
    Err(DecryptError::Decrypt)
}
