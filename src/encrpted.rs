use crate::aes::aes_256_cbc_decrypt_unpadded;
use crate::common::DecryptError;
use log::debug;

/// Decrypts encrypted firmware that uses the 'encrpted_img' format, primarily the DIR-X series
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Actual encrypted data starts at offset 16
    const CIPHER_DATA_START: usize = 16;

    // Expected magic bytes of the encrypted and decrypted data
    const ENCRYPTED_MAGIC_BYTES: &[u8] = b"encrpted_img";
    const DECRYPTED_MAGIC_BYTES: &[u8] = b"UBI";

    // From https://www.youtube.com/watch?v=PPc5yDTFJFU
    const IV: &[u8] = b"\x4a\x25\x31\x69\x51\x6c\x38\x24\x3d\x6c\x6d\x2d\x3b\x38\x41\x45";
    const AES_KEY: &[u8] = b"\x68\x65\x39\x2d\x34\x2b\x4d\x21\x29\x64\x36\x3d\x6d\x7e\x77\x65\x31\x2c\x71\x32\x61\x33\x64\x31\x6e\x26\x32\x2a\x5a\x5e\x25\x38";

    // Check the encrypted data magic signature
    if let Some(enc_magic) = encrypted_data.get(0..ENCRYPTED_MAGIC_BYTES.len()) {
        if enc_magic == ENCRYPTED_MAGIC_BYTES {
            // Get the actual encrypted data
            if let Some(cipher_data) = encrypted_data.get(CIPHER_DATA_START..) {
                // Decrypt the encrypted data
                match aes_256_cbc_decrypt_unpadded(cipher_data, AES_KEY, IV) {
                    Err(e) => {
                        debug!("Decrypt error: {}", e);
                        Err(DecryptError::Decrypt)
                    }
                    Ok(decrypted_data) => {
                        // Sanity check the decrypted data magic (expected to be a UBI image)
                        if let Some(dec_magic) = decrypted_data.get(0..DECRYPTED_MAGIC_BYTES.len())
                        {
                            if dec_magic == DECRYPTED_MAGIC_BYTES {
                                Ok(decrypted_data)
                            } else {
                                debug!("Decrypted magic bytes do not match");
                                Err(DecryptError::Output)
                            }
                        } else {
                            debug!("Decrypted data too small");
                            Err(DecryptError::Output)
                        }
                    }
                }
            } else {
                debug!("Failed to read encrypted data");
                Err(DecryptError::Input)
            }
        } else {
            debug!("Encrypted magic bytes do not match");
            Err(DecryptError::Input)
        }
    } else {
        debug!("Failed to read encrypted magic bytes");
        Err(DecryptError::Input)
    }
}
