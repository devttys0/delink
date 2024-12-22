use crate::common::DecryptError;
use crate::openssl::{aes_256_cbc_decrypt, MessageDigest};
use crate::sha1_hmac::sha1_hmac_string;
use log::debug;

/// Decrypt encrypted D-Link TLV firmware
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Expected magic bytes of the encrypted and decrypted firmware
    const ENCRYPTED_MAGIC: &[u8] = b"\x64\x80\x19\x40";

    // OpenSSL encrypted data is expected to start at this offset inside the firmware
    const HEADER_SIZE: usize = 0x74;
    const OPENSSL_DATA_OFFSET: usize = HEADER_SIZE;

    // Check the expected firmware magic bytes
    if let Some(encrypted_magic) = encrypted_data.get(0..ENCRYPTED_MAGIC.len()) {
        if encrypted_magic == ENCRYPTED_MAGIC {
            // Get the firmware header bytes
            if let Some(firmware_header) = encrypted_data.get(0..HEADER_SIZE) {
                // Derive the encryption key from the firmware header strings
                let decryption_key = keygen(firmware_header);

                debug!("Trying key: {}", decryption_key);

                // Get the OpenSSL encrypted data
                if let Some(openssl_data) = encrypted_data.get(OPENSSL_DATA_OFFSET..) {
                    // Decrypt it
                    if let Ok(decrypted_data) =
                        aes_256_cbc_decrypt(openssl_data, &decryption_key, MessageDigest::MD5, None)
                    {
                        return Ok(decrypted_data);
                    } else {
                        debug!("Failed to decrypt with known key");
                        return Err(DecryptError::Decrypt);
                    }
                } else {
                    debug!("Failed to read encrypted data");
                    return Err(DecryptError::Input);
                }
            } else {
                debug!("Failed to read firmware header");
                return Err(DecryptError::Input);
            }
        } else {
            debug!("Encrypted magic bytes do not match");
            return Err(DecryptError::Input);
        }
    }

    debug!("Failed to read encrypted magic bytes");
    Err(DecryptError::Decrypt)
}

/// Decryption key is a SHA1 hash generated from the model name and board ID stored in the firmware header
fn keygen(firmware_header: &[u8]) -> String {
    const MAX_STRING_SIZE: usize = 0x20;

    const MODEL_NAME_START: usize = 4;
    const MODEL_NAME_END: usize = MODEL_NAME_START + MAX_STRING_SIZE;

    const BOARD_ID_START: usize = MODEL_NAME_END;
    const BOARD_ID_END: usize = BOARD_ID_START + MAX_STRING_SIZE;

    let board_id = get_cstring(&firmware_header[BOARD_ID_START..BOARD_ID_END]);
    let model_name = get_cstring(&firmware_header[MODEL_NAME_START..MODEL_NAME_END]);

    sha1_hmac_string(&board_id, &model_name)
}

/// Read bytes from data until a NULL byte is found
fn get_cstring(data: &[u8]) -> Vec<u8> {
    let mut cstring: Vec<u8> = Vec::new();

    for b in data {
        if *b == 0 {
            break;
        } else {
            cstring.push(*b);
        }
    }

    cstring
}
