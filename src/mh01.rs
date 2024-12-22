use crate::common::DecryptError;
use crate::openssl::{aes_128_cbc_decrypt, MessageDigest};
use log::{debug, warn};
use std::collections::HashMap;

/// Returns a HashMap of known encryption passphrases and their descriptions
pub fn known_keys() -> HashMap<String, String> {
    HashMap::from([
        (
            "044b4e59846ecee953662ff2238fcc23".to_string(),
            "E15 v1.00 - v1.20".to_string(),
        ),
        (
            "927fc5786df1a9557524a0289e1e3f3b".to_string(),
            "E15 > v1.20".to_string(),
        ),
        (
            "4d5ee2c8b5d0fdd9a9a2d351ba897752".to_string(),
            "E30 v1.00 - v1.10".to_string(),
        ),
        (
            "238a29b9432f688e30b701548c753146".to_string(),
            "E30 > v1.10".to_string(),
        ),
        (
            "a4f7c17c3e0aa4532c2024ce6ac5f17c".to_string(),
            "R12 v1.00 - v1.10".to_string(),
        ),
        (
            "6b5a65dbc1ebc492ac6d8efbbb59ae09".to_string(),
            "R12 > v1.10".to_string(),
        ),
        (
            "70070e579f97548a96a7794d4d779376".to_string(),
            "R15 v1.00 - v1.20".to_string(),
        ),
        (
            "7b4df82f7f042b9d0b40971be0ff53c4".to_string(),
            "R15 > v1.20".to_string(),
        ),
        (
            "6276ccf4c1d8d6f54b481095e78ff97f".to_string(),
            "R18".to_string(),
        ),
        (
            "1ae6c79be7d069ca74df7670bdfc4952".to_string(),
            "M18".to_string(),
        ),
        (
            "b4517d9b98e04d9f075f5e78c743e097".to_string(),
            "M30 v1.02 - v1.10".to_string(),
        ),
        (
            "05c79b73cf88619d7b9725505cfd718f".to_string(),
            "M30 > v1.10".to_string(),
        ),
        (
            "6b29f1d663a21b35fb45b69a42649f5e".to_string(),
            "M32 v1.00 - 1.10".to_string(),
        ),
        (
            "1bfb1004e29f9eb76dbe26eb0dd87cd1".to_string(),
            "M32 > v1.10".to_string(),
        ),
        (
            "c5f8a1e22f808abc84f2e4a6fa5f10bb".to_string(),
            "M60 v1.10".to_string(),
        ),
        (
            "6420da70a975455e4ddd6b8fa5b652e7".to_string(),
            "M60 > v1.10".to_string(),
        ),
    ])
}

/// Decrypt D-Link MH01 firmware
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Encrypted firmware starts with these magic bytes
    const ENCRYPTED_MAGIC: &[u8] = b"MH01";

    // There is a header before the encrypted data
    const HEADER_SIZE: usize = 0x41;

    // Firmware header contains the IV, in ASCII hex
    const IV_START: usize = 32;
    const IV_END: usize = IV_START + 32;

    const ENCRYPTED_DATA_SIZE_FIELD_START: usize = 0x18;
    const ENCRYPTED_DATA_SIZE_FIELD_END: usize = ENCRYPTED_DATA_SIZE_FIELD_START + 4;

    // Expected magic bytes of the decrypted data
    const DECRYPTED_MAGIC: &[u8] = b"MH01";
    const DECRYPTED_MAGIC_START: usize = 0;
    const DECRYPTED_MAGIC_END: usize = DECRYPTED_MAGIC_START + DECRYPTED_MAGIC.len();

    // Validate the encrypted firmware header magic bytes
    if let Some(encrypted_magic) = encrypted_data.get(0..ENCRYPTED_MAGIC.len()) {
        if encrypted_magic == ENCRYPTED_MAGIC {
            // Get the size of the encrypted data
            if let Some(encrypted_size_bytes) =
                encrypted_data.get(ENCRYPTED_DATA_SIZE_FIELD_START..ENCRYPTED_DATA_SIZE_FIELD_END)
            {
                let encrypted_data_size =
                    u32::from_le_bytes(encrypted_size_bytes.try_into().unwrap()) as usize;

                // Calculate the start and end offsets of the encrypted data
                let cipher_data_start: usize = HEADER_SIZE;
                let cipher_data_end: usize = cipher_data_start + encrypted_data_size;

                // Get the IV data (ASCII hex) and decode it
                if let Some(iv_ascii) = encrypted_data.get(IV_START..IV_END) {
                    match hex::decode(iv_ascii) {
                        Err(e) => {
                            debug!("Invalid ASCII IV: {}", e);
                            return Err(DecryptError::Input);
                        }
                        Ok(iv) => {
                            // Get the encrypted data
                            if let Some(cipher_data) =
                                encrypted_data.get(cipher_data_start..cipher_data_end)
                            {
                                // Try to decrypt with known encryption keys
                                for (password, name) in known_keys().iter() {
                                    debug!("Trying {} decryption key", name);

                                    if let Ok(decrypted_data) = aes_128_cbc_decrypt(
                                        cipher_data,
                                        password,
                                        MessageDigest::SHA256,
                                        Some(&iv),
                                    ) {
                                        // Decryption suceeded, check decrypted magic bytes
                                        if let Some(decrypted_magic) = decrypted_data
                                            .get(DECRYPTED_MAGIC_START..DECRYPTED_MAGIC_END)
                                        {
                                            if decrypted_magic == DECRYPTED_MAGIC {
                                                return Ok(decrypted_data);
                                            } else {
                                                warn!("Decrypted magic bytes do not match");
                                            }
                                        } else {
                                            warn!("Failed to read decrypted magic bytes");
                                        }
                                    } else {
                                        warn!("Decryption failed");
                                    }
                                }
                            } else {
                                debug!("Failed to read encrypted data");
                                return Err(DecryptError::Input);
                            }
                        }
                    }
                } else {
                    debug!("Failed to read IV from encrypted data");
                    return Err(DecryptError::Input);
                }
            } else {
                debug!("Failed to read encrypted data size");
                return Err(DecryptError::Input);
            }
        } else {
            debug!("Encrypted magic bytes do not match");
            return Err(DecryptError::Input);
        }
    } else {
        debug!("Failed to read encrypted header magic bytes");
        return Err(DecryptError::Input);
    }

    debug!("All decryption keys failed");
    Err(DecryptError::Decrypt)
}
