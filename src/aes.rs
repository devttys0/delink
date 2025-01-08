use crate::common::DecryptError;
use aes::cipher::{block_padding::Pkcs7, BlockCipher, BlockDecrypt, BlockDecryptMut, KeyIvInit};
use log::warn;

pub enum AesKeySize {
    AES128 = 16,
    _AES192 = 24,
    AES256 = 32,
}

/// Supported AES variants for decryption
#[derive(Debug)]
enum AesVariant {
    Aes128(cbc::Decryptor<aes::Aes128>),
    Aes192(cbc::Decryptor<aes::Aes192>),
    Aes256(cbc::Decryptor<aes::Aes256>),
}

/// Padding modes for AES decryption
#[derive(Debug, Clone, Copy)]
pub enum AesPaddingMode {
    /// No padding - input must be a multiple of the block size
    NoPadding,
    /// PKCS7 padding
    WithPadding,
}

impl AesVariant {
    /// Creates a new AES variant with the specified key size
    fn new(key: &[u8], iv: &[u8], key_size: AesKeySize) -> Result<Self, DecryptError> {
        let key_size = key_size as usize;
        let cropped_key = key
            .get(..key_size)
            .ok_or(DecryptError::InvalidKeySize(key.len()))?;

        match key_size {
            16 => Ok(AesVariant::Aes128(cbc::Decryptor::new(
                cropped_key.into(),
                iv.into(),
            ))),
            24 => Ok(AesVariant::Aes192(cbc::Decryptor::new(
                cropped_key.into(),
                iv.into(),
            ))),
            32 => Ok(AesVariant::Aes256(cbc::Decryptor::new(
                cropped_key.into(),
                iv.into(),
            ))),
            size => Err(DecryptError::InvalidKeySize(size)),
        }
    }

    /// Decrypts data without padding
    fn decrypt_unpadded<C: BlockCipher + BlockDecrypt>(
        mut decryptor: cbc::Decryptor<C>,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        if encrypted_data.len() % C::block_size() != 0 {
            return Err(DecryptError::InvalidInputLength);
        }

        let mut output_buffer = vec![0; encrypted_data.len()];
        for (chunk, output) in encrypted_data
            .chunks(C::block_size())
            .zip(output_buffer.chunks_mut(C::block_size()))
        {
            decryptor.decrypt_block_b2b_mut(chunk.into(), output.into());
        }
        Ok(output_buffer)
    }

    /// Decrypts data with PKCS7 padding
    fn decrypt_padded<C: BlockCipher + BlockDecryptMut>(
        decryptor: cbc::Decryptor<C>,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut decrypted_buf = vec![0; encrypted_data.len()];
        decryptor
            .decrypt_padded_b2b_mut::<Pkcs7>(encrypted_data, &mut decrypted_buf)
            .map(|data| data.to_vec())
            .map_err(|_| {
                warn!("Decryption failed with padding");
                DecryptError::Decrypt
            })
    }

    /// Decrypts data using the appropriate method based on padding mode
    fn decrypt(
        &self,
        encrypted_data: &[u8],
        padding: AesPaddingMode,
    ) -> Result<Vec<u8>, DecryptError> {
        match (self, padding) {
            (AesVariant::Aes128(decryptor), AesPaddingMode::NoPadding) => {
                Self::decrypt_unpadded(decryptor.clone(), encrypted_data)
            }
            (AesVariant::Aes128(decryptor), AesPaddingMode::WithPadding) => {
                Self::decrypt_padded(decryptor.clone(), encrypted_data)
            }
            (AesVariant::Aes192(decryptor), AesPaddingMode::NoPadding) => {
                Self::decrypt_unpadded(decryptor.clone(), encrypted_data)
            }
            (AesVariant::Aes192(decryptor), AesPaddingMode::WithPadding) => {
                Self::decrypt_padded(decryptor.clone(), encrypted_data)
            }
            (AesVariant::Aes256(decryptor), AesPaddingMode::NoPadding) => {
                Self::decrypt_unpadded(decryptor.clone(), encrypted_data)
            }
            (AesVariant::Aes256(decryptor), AesPaddingMode::WithPadding) => {
                Self::decrypt_padded(decryptor.clone(), encrypted_data)
            }
        }
    }
}

/// Generic AES-CBC decryption function
///
/// # Arguments
///
/// * `encrypted_data` - The data to decrypt
/// * `key` - The encryption key
/// * `iv` - The initialization vector
/// * `key_size` - Size of the key in bytes (16 for AES-128, 32 for AES-256)
/// * `padding` - The padding mode to use
///
/// # Returns
///
/// The decrypted data or a DecryptError
pub fn aes_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
    key_size: AesKeySize,
    padding: AesPaddingMode,
) -> Result<Vec<u8>, DecryptError> {
    let decryptor = AesVariant::new(key, iv, key_size)?;
    decryptor.decrypt(encrypted_data, padding)
}

/// Convenience function for AES-128-CBC decryption with padding
pub fn aes_128_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::AES128,
        AesPaddingMode::WithPadding,
    )
}

/// Convenience function for AES-128-CBC decryption without padding
pub fn aes_128_cbc_decrypt_unpadded(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::AES128,
        AesPaddingMode::NoPadding,
    )
}

/// Convenience function for AES-192-CBC decryption with padding
pub fn _aes_192_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::_AES192,
        AesPaddingMode::WithPadding,
    )
}

/// Convenience function for AES-192-CBC decryption without padding
pub fn _aes_192_cbc_decrypt_unpadded(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::_AES192,
        AesPaddingMode::NoPadding,
    )
}

/// Convenience function for AES-256-CBC decryption with padding
pub fn aes_256_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::AES256,
        AesPaddingMode::WithPadding,
    )
}

/// Convenience function for AES-256-CBC decryption without padding
pub fn aes_256_cbc_decrypt_unpadded(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::AES256,
        AesPaddingMode::NoPadding,
    )
}
