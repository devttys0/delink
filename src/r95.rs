use crate::common::DecryptError;
use crate::openssl::{aes_256_cbc_decrypt, MessageDigest};
use log::debug;

/// Decrypt R95/M95/R36/M36 firmware
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Decrypted data is expected to be a DTB file
    const MAGIC: &[u8] = b"\xd0\x0d\xfe\xed";
    const MAGIC_START: usize = 0;
    const MAGIC_END: usize = MAGIC_START + MAGIC.len();
    const OPENSSL_MAGIC: &[u8] = b"Salted__";

    // Known encryption passwords for these models
    let passwords: Vec<String> = vec![
        // R36
        "CAD1C42B11F1982FFA94B6A24C260A43".to_string(),
        // M36
        "A11E331C15CE73ABA8E06171A11D2FB6".to_string(),
        // R95
        "BE81AE1B6F523AC7164C4FD67B6BD8FD".to_string(),
        // M95
        "91A9A3AF2218F4EA60AC37D5835EB318".to_string(),
    ];

    // Check if openssl magic bytes are at offset 512; else, assume offset 0
    let mut offset: usize = 0;
    if let Some(magic_bytes) = encrypted_data.get(512..520) {
        if magic_bytes == OPENSSL_MAGIC {
            offset = 512;
        }
    }

    for password in passwords {
        if let Ok(decrypted_data) = aes_256_cbc_decrypt(
            &encrypted_data[offset..],
            &password,
            MessageDigest::SHA256,
            None,
        ) {
            if let Some(magic) = decrypted_data.get(MAGIC_START..MAGIC_END) {
                if magic == MAGIC {
                    return Ok(decrypted_data);
                }
            }
        }
    }

    debug!("Failed to decrypt with known keys");
    Err(DecryptError::Decrypt)
}
