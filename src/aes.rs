use crate::common::DecryptError;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::{aes, blockmodes};
use log::warn;

/// Performs AES CBC decryption on the encrypted data using the provided AES key and initialization vector
pub fn cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
    key_size: aes::KeySize,
) -> Result<Vec<u8>, DecryptError> {
    let mut output_buffer = [0; 0x2000];
    let mut decrypted_data: Vec<u8> = Vec::new();

    let mut read_buffer = RefReadBuffer::new(encrypted_data);
    let mut write_buffer = RefWriteBuffer::new(&mut output_buffer);

    let mut decryptor = aes::cbc_decryptor(key_size, key, iv, blockmodes::PkcsPadding);

    loop {
        match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Err(e) => {
                warn!("AES CBC error: {:?}", e);
                break;
            }
            Ok(result) => {
                // Get the decrypted data buffer
                //decrypted_data.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
                decrypted_data.extend(
                    write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .copied(),
                );

                // Check if there is more data to decrypt, or if we're done
                match result {
                    BufferResult::BufferUnderflow => {
                        return Ok(decrypted_data);
                    }
                    BufferResult::BufferOverflow => {
                        continue;
                    }
                }
            }
        }
    }

    Err(DecryptError::Decrypt)
}

/// Performs AES-256-CBC decryption on the encrypted data using the provided AES key and initialization vector
pub fn aes_256_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    cbc_decrypt(encrypted_data, key, iv, aes::KeySize::KeySize256)
}

/// Performs AES-128-CBC decryption on the encrypted data using the provided AES key and initialization vector
pub fn aes_128_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    cbc_decrypt(encrypted_data, key, iv, aes::KeySize::KeySize128)
}
