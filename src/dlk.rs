use crate::aes::aes_256_cbc_decrypt;
use crate::common::DecryptError;
use crate::mh01::known_keys;
use log::{debug, warn};

/// Decrypt D-Link DLK firmware
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Encrypted firmware starts with these magic bytes
    const ENCRYPTED_MAGIC: &[u8] = b"DLK";

    // There are two headers, each of this size, prior to the encrypted data
    const HEADER_SIZE: usize = 0x50;
    const IV_SIZE: usize = 16;

    // Number of padding bytes for each encrypted data block
    const BLOCK_PADDING_SIZE: usize = 0x20;

    // Relative location of the block size field in the header
    const BLOCK_SIZE_OFFSET: usize = 0x10;
    const BLOCK_SIZE_LEN: usize = std::mem::size_of::<u32>();

    // Relative location of the payload size field in the header
    const PAYLOAD_SIZE_OFFSET: usize = 0x2C;
    const PAYLOAD_SIZE_LEN: usize = std::mem::size_of::<u32>();

    // Validate the signature header's magic bytes
    match encrypted_data.get(0..ENCRYPTED_MAGIC.len()) {
        None => {
            debug!("Failed to read signature header magic bytes");
            return Err(DecryptError::Input);
        }
        Some(header1_magic) => {
            if header1_magic == ENCRYPTED_MAGIC {
                // Calculate the offset of the payload size field for this header
                let signature_size_start = PAYLOAD_SIZE_OFFSET;
                let signature_size_end = signature_size_start + PAYLOAD_SIZE_LEN;

                // Get the size of the first header's payload data (the firmware signature)
                match encrypted_data.get(signature_size_start..signature_size_end) {
                    None => {
                        debug!("Failed to read signature size field");
                        return Err(DecryptError::Input);
                    }
                    Some(signature_size_bytes) => {
                        let signature_size =
                            u32::from_le_bytes(signature_size_bytes.try_into().unwrap()) as usize;
                        let next_header_offset = HEADER_SIZE + signature_size;

                        // Validate the payload header's magic bytes
                        match encrypted_data
                            .get(next_header_offset..next_header_offset + ENCRYPTED_MAGIC.len())
                        {
                            None => {
                                debug!("Failed to read payload header magic bytes");
                                return Err(DecryptError::Input);
                            }
                            Some(header2_magic) => {
                                if header2_magic == ENCRYPTED_MAGIC {
                                    // Calculate the offset of the block size field
                                    let block_size_start = next_header_offset + BLOCK_SIZE_OFFSET;
                                    let block_size_end = block_size_start + BLOCK_SIZE_LEN;

                                    // Calculate the offset of the total size field
                                    let total_size_start = next_header_offset + PAYLOAD_SIZE_OFFSET;
                                    let total_size_end = total_size_start + PAYLOAD_SIZE_LEN;

                                    // Get the block size field
                                    match encrypted_data.get(block_size_start..block_size_end) {
                                        None => {
                                            debug!("Failed to read data block size");
                                            return Err(DecryptError::Input);
                                        }
                                        Some(block_size_bytes) => {
                                            // Interpret block size field as little endian u32
                                            let block_size = (u32::from_le_bytes(
                                                block_size_bytes.try_into().unwrap(),
                                            )
                                                as usize)
                                                + BLOCK_PADDING_SIZE;

                                            // Get the total size field
                                            match encrypted_data
                                                .get(total_size_start..total_size_end)
                                            {
                                                None => {
                                                    debug!("Failed to read encrypted data size");
                                                    return Err(DecryptError::Input);
                                                }
                                                Some(total_size_bytes) => {
                                                    // Interpret total size field as little endian u32
                                                    let total_data_size = u32::from_le_bytes(
                                                        total_size_bytes.try_into().unwrap(),
                                                    )
                                                        as usize;

                                                    // Calculate the start and end offsets of the array of encrypted blocks
                                                    let cipher_data_start =
                                                        next_header_offset + HEADER_SIZE;
                                                    let cipher_data_end =
                                                        cipher_data_start + total_data_size;

                                                    // Get the bytes of all encrypted blocks
                                                    match encrypted_data
                                                        .get(cipher_data_start..cipher_data_end)
                                                    {
                                                        None => {
                                                            debug!("Failed to read encrypted data [{:#X} - {:#X}]", cipher_data_start, cipher_data_end);
                                                            return Err(DecryptError::Input);
                                                        }
                                                        Some(block_data) => {
                                                            // Loop through all known keys
                                                            for (key, name) in known_keys().iter() {
                                                                debug!("Trying {} key...", name);

                                                                let mut decrypted_data: Vec<u8> =
                                                                    Vec::new();
                                                                let mut processed_data_size: usize =
                                                                    0;

                                                                // Loop through each encrypted block
                                                                for block in
                                                                    block_data.chunks(block_size)
                                                                {
                                                                    // A block consists of a 16-byte IV followed by the encrypted data;
                                                                    // hence a valid block must have more than 16 bytes in it.
                                                                    if block.len() <= IV_SIZE {
                                                                        warn!(
                                                                            "Block is too small!"
                                                                        );
                                                                        break;
                                                                    }

                                                                    // Separate out the IV from the encrypted block data
                                                                    let iv = &block[0..IV_SIZE];
                                                                    let encrypted_block =
                                                                        &block[IV_SIZE..];

                                                                    // Decrypt the block
                                                                    match aes_256_cbc_decrypt(
                                                                        encrypted_block,
                                                                        &key.clone().into_bytes(),
                                                                        iv,
                                                                    ) {
                                                                        Err(_) => {
                                                                            break;
                                                                        }
                                                                        Ok(decrypted_block) => {
                                                                            // Track how much data has been successfully decrypted and add the decrypted data to decrypted_data
                                                                            processed_data_size +=
                                                                                block.len();
                                                                            decrypted_data.extend(
                                                                                decrypted_block,
                                                                            );
                                                                        }
                                                                    }
                                                                }

                                                                // If all data was decrypted successfully, return success
                                                                if processed_data_size
                                                                    == total_data_size
                                                                {
                                                                    return Ok(decrypted_data);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    debug!("All decryption keys failed");
    Err(DecryptError::Decrypt)
}
