use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Generates a SHA1 from an HMAC key and message
pub fn sha1_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hasher: Hmac<Sha1> = Mac::new_from_slice(key).expect("Failed to instantiate Mac");
    hasher.update(message);
    hasher.finalize().into_bytes().to_vec()
}

/// Same as sha1_hmac, but returns the SHA1 hash as an ASCII hex string
pub fn sha1_hmac_string(key: &[u8], message: &[u8]) -> String {
    hex::encode(sha1_hmac(key, message))
}
