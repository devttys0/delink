use crate::aes::aes_128_cbc_decrypt_unpadded;
use crate::common::DecryptError;
use log::debug;

/// Decrypts SHRS firmware, used by many D-Link models.
/// Original work: <https://github.com/0xricksanchez/dlink-decrypt/blob/master/dlink-dec.py>
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Magic bytes of the encrypted firmware
    const SHRS_MAGIC: &[u8] = b"SHRS";
    const MAGIC_START: usize = 0;

    // Location of the IV in the firmware header
    const IV_START: usize = 0x0C;
    const IV_END: usize = IV_START + 16;

    // Location of the encrypted data size field in the firmware header
    const ENC_SIZE_START: usize = 8;
    const ENC_SIZE_END: usize = ENC_SIZE_START + 4;

    // Location of the start of encrypted data, after the firmware header
    const ENCRYPTED_DATA_START: usize = 0x6DC;

    // Expected magic bytes of the decrypted data
    const DECRYPTED_MAGIC: &[u8] = b"\x27\x05\x19\x56";

    // AES key to decrypt the encrypted data
    const AES_KEY: &[u8] = b"\xC0\x5F\xBF\x19\x36\xC9\x94\x29\xCE\x2A\x07\x81\xF0\x8D\x6A\xD8";

    // Validate the firmware header magic bytes
    if let Some(shrs_magic) = encrypted_data.get(MAGIC_START..SHRS_MAGIC.len()) {
        if shrs_magic == SHRS_MAGIC {
            // Get the size of the encrypted data
            if let Some(encrypted_size_bytes) = encrypted_data.get(ENC_SIZE_START..ENC_SIZE_END) {
                let encrypted_data_size: usize =
                    u32::from_be_bytes(encrypted_size_bytes.try_into().unwrap()) as usize;

                // Get the IV used to encrypt the data
                if let Some(iv) = encrypted_data.get(IV_START..IV_END) {
                    // Calculate the start and end offsets of the encrypted data
                    let encrypted_data_start = ENCRYPTED_DATA_START;
                    let encrypted_data_end = encrypted_data_start + encrypted_data_size;

                    // Get the encrypted data
                    if let Some(cipher_data) =
                        encrypted_data.get(encrypted_data_start..encrypted_data_end)
                    {
                        // Decrypt the encrypted data
                        if let Ok(decrypted_data) = aes_128_cbc_decrypt_unpadded(cipher_data, AES_KEY, iv) {
                            // Validate the magic bytes of the decrypted data
                            if let Some(decrypted_magic) =
                                decrypted_data.get(MAGIC_START..DECRYPTED_MAGIC.len())
                            {
                                if decrypted_magic == DECRYPTED_MAGIC {
                                    Ok(decrypted_data)
                                } else {
                                    debug!("Decrypted magic bytes do not match");
                                    Err(DecryptError::Output)
                                }
                            } else {
                                debug!("Failed to read expected magic bytes from decrypted output");
                                Err(DecryptError::Output)
                            }
                        } else {
                            debug!("SHRS decryption failed");
                            Err(DecryptError::Decrypt)
                        }
                    } else {
                        debug!("Failed to read SHRS encrypted data");
                        Err(DecryptError::Input)
                    }
                } else {
                    debug!("Failed to read SHRS IV");
                    Err(DecryptError::Input)
                }
            } else {
                debug!("SHRS magic bytes do not match");
                Err(DecryptError::Input)
            }
        } else {
            debug!("Encrypted magic bytes do not match");
            Err(DecryptError::Input)
        }
    } else {
        debug!("Failed to read the SHRS magic bytes");
        Err(DecryptError::Input)
    }
}
