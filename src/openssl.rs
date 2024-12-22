use crate::aes;
use crate::common::DecryptError;
use log::warn;

/// The type of hash to use when generating a key/iv pair from a passphrase
#[derive(Clone, Debug)]
pub enum MessageDigest {
    MD5,
    SHA256,
}

/// AES key size to use
#[derive(Clone, Debug)]
pub enum KeySize {
    AES128,
    AES256,
}

#[derive(Clone, Default, Debug)]
struct OpenSSLCryptInfo {
    iv: Vec<u8>,
    key: Vec<u8>,
}

/// Returns the SHA256 hash of the provided data
fn sha256_digest(data: &[u8]) -> Vec<u8> {
    // This *should* never fail
    hex::decode(sha256::digest(data)).expect("Failed to decode SHA256 hash")
}

/// Returns the MD5 hash of the provided data
fn md5_digest(data: &[u8]) -> Vec<u8> {
    // There has to be a cleaner way to do this, but it works...
    hex::decode(format!("{:x}", md5::compute(data))).expect("Failed to decode MD5 hash")
}

/// Returns the request hash of the provided data
fn digest(data: &[u8], hash_type: &MessageDigest) -> Vec<u8> {
    match hash_type {
        MessageDigest::MD5 => md5_digest(data),
        MessageDigest::SHA256 => sha256_digest(data),
    }
}

/// Calculates the encryption key and IV from the password and salt values.
fn derive_key_iv(
    password: &str,
    salt: &[u8],
    hash_type: MessageDigest,
    iv: Option<&[u8]>,
) -> OpenSSLCryptInfo {
    const IV_LEN: usize = 16;
    const KEY_LEN: usize = 32;
    const TOTAL_LEN: usize = IV_LEN + KEY_LEN;

    let mut hash: Vec<u8>;
    let mut key_material: Vec<u8>;
    let mut pass_salt: Vec<u8> = Vec::new();
    let mut crypt_info = OpenSSLCryptInfo {
        ..Default::default()
    };

    // Concatenate password and salt
    pass_salt.extend(password.bytes());
    pass_salt.extend(salt);

    // Generate a hash of the password + salt
    hash = digest(&pass_salt, &hash_type);
    key_material = hash.clone();

    // Loop until dtot is the length of the key + length of the iv
    while key_material.len() < TOTAL_LEN {
        let mut hash_input: Vec<u8> = Vec::new();

        // Input to this hash calculation is the last hash computed + password + salt
        hash_input.extend(hash);
        hash_input.extend(pass_salt.clone());

        // Create a new hash from the last hash + password + salt
        hash = digest(&hash_input, &hash_type);

        // Append the most recently calcualted hash to key_material
        key_material.extend(hash.clone());
    }

    crypt_info.key = key_material[0..KEY_LEN].to_vec();

    match iv {
        None => {
            crypt_info.iv = key_material[KEY_LEN..TOTAL_LEN].to_vec();
        }
        Some(user_supplied_iv) => {
            crypt_info.iv = user_supplied_iv.to_vec();
        }
    }

    crypt_info
}

/// Decrypts an OpenSSL encrypted file
pub fn decrypt(
    openssl_data: &[u8],
    password: &str,
    key_size: KeySize,
    hash_type: MessageDigest,
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, DecryptError> {
    const OPENSSL_FILE_MAGIC: &[u8] = b"Salted__";

    // Get and validate the magic file bytes
    if let Some(magic) = openssl_data.get(0..8) {
        if magic == OPENSSL_FILE_MAGIC {
            // Get the 64-bit salt value
            if let Some(salt) = openssl_data.get(8..16) {
                // Derive the encryption key and IV from the salt and provided password
                let crypt = derive_key_iv(password, salt, hash_type, iv);

                // Everything after the salt is the encrypted data
                if let Some(encrypted_data) = openssl_data.get(16..) {
                    // Perform the requested decryption
                    match key_size {
                        KeySize::AES128 => {
                            aes::aes_128_cbc_decrypt(encrypted_data, &crypt.key, &crypt.iv)
                        }
                        KeySize::AES256 => {
                            aes::aes_256_cbc_decrypt(encrypted_data, &crypt.key, &crypt.iv)
                        }
                    }
                } else {
                    warn!("Failed to read OpenSSL encrypted data");
                    Err(DecryptError::Input)
                }
            } else {
                warn!("Failed to read OpenSSL salt");
                Err(DecryptError::Input)
            }
        } else {
            warn!("OpenSSL file magic does not match");
            Err(DecryptError::Input)
        }
    } else {
        warn!("Failed to read OpenSSL magic bytes");
        Err(DecryptError::Input)
    }
}

/// Decrypts OpenSSL encrypted data using AES-256-CBC
pub fn aes_256_cbc_decrypt(
    openssl_data: &[u8],
    password: &str,
    hash_type: MessageDigest,
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, DecryptError> {
    decrypt(openssl_data, password, KeySize::AES256, hash_type, iv)
}

/// Decrypts OpenSSL encrypted data using AES-128-CBC
pub fn aes_128_cbc_decrypt(
    openssl_data: &[u8],
    password: &str,
    hash_type: MessageDigest,
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, DecryptError> {
    decrypt(openssl_data, password, KeySize::AES128, hash_type, iv)
}
