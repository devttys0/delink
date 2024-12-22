use crate::common::{DecryptError, DecryptorFunction};
use crate::dap1610;
use crate::dlk;
use crate::encimg;
use crate::encrpted;
use crate::mh01;
use crate::shrs;
use crate::tlv;
use log::trace;

/// Attempts to decrypt the provided data using all decryptors
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // List of supported decryptors
    let decryptors: Vec<(&str, DecryptorFunction)> = vec![
        ("shrs", shrs::decrypt),
        ("mh01", mh01::decrypt),
        ("dlk", dlk::decrypt),
        ("encimg", encimg::decrypt),
        ("tlv", tlv::decrypt),
        ("dap1610", dap1610::decrypt),
        ("encrpted_img", encrpted::decrypt),
    ];

    // Try each decryptor until one works
    for (name, decryptor) in decryptors {
        trace!("Trying decryptor: {}", name);
        if let Ok(decrypted_data) = (decryptor)(encrypted_data) {
            return Ok(decrypted_data);
        }
    }

    Err(DecryptError::Decrypt)
}
