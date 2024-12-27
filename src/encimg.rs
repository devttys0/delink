use crate::aes::aes_256_cbc_decrypt_unpadded;
use crate::common::DecryptError;
use log::{debug, warn};

#[derive(Clone, Debug, Default)]
struct EncimgFirmware {
    name: String,
    encrypted_data_offset: usize,
    image_sign: Option<Vec<u8>>,
    image_sign_offset: Option<usize>,
}

/// Decrypts firmware that has been encrypted using D-Link's encimg tool.
pub fn decrypt(encrypted_image: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Length of all possible decrypted magic bytes
    const MAGIC_LEN: usize = 4;

    // Valid decrypted magic bytes
    let known_decrypted_magics: Vec<Vec<u8>> = vec![
        b"\x5E\xA3\xA4\x17".to_vec(),
        b"\xD0\x0D\xFE\xED".to_vec(),
        b"\x5D\x00\x00\x80".to_vec(),
    ];

    // All known firmware images and their associated image_sign values.
    // Some are re-used amongst other devices.
    let known_firmwares: Vec<EncimgFirmware> = vec![
        EncimgFirmware {
            name: "DAP-1665".to_string(),
            image_sign: Some(b"wapac25_dlink.2015_dap1665".to_vec()),
            image_sign_offset: None,
            encrypted_data_offset: 0,
        },
        EncimgFirmware {
            name: "DIR-822".to_string(),
            image_sign: Some(b"wrgac43s_dlink.2015_dir822c1".to_vec()),
            image_sign_offset: None,
            encrypted_data_offset: 0,
        },
        EncimgFirmware {
            name: "DIR-842".to_string(),
            image_sign: Some(b"wrgac65_dlink.2015_dir842".to_vec()),
            image_sign_offset: None,
            encrypted_data_offset: 0,
        },
        EncimgFirmware {
            name: "DIR-850L A1".to_string(),
            image_sign: Some(b"wrgac05_dlob.hans_dir850l".to_vec()),
            image_sign_offset: None,
            encrypted_data_offset: 0,
        },
        EncimgFirmware {
            name: "DIR-850L B1".to_string(),
            image_sign: Some(b"wrgac25_dlink.2013gui_dir850l".to_vec()),
            image_sign_offset: None,
            encrypted_data_offset: 0,
        },
        EncimgFirmware {
            name: "DIR-2610".to_string(),
            image_sign: None,
            image_sign_offset: Some(0),
            encrypted_data_offset: 0xA0,
        },
    ];

    // Loop through all known firmwares
    for firmware in known_firmwares {
        // An image_sign value is required
        assert!(firmware.image_sign.is_some() || firmware.image_sign_offset.is_some());

        // Get the image_sign
        let image_sign = match firmware.image_sign_offset {
            None => firmware.image_sign.unwrap(),
            Some(image_sign_offset) => match encrypted_image.get(image_sign_offset..) {
                None => b"".to_vec(),
                Some(image_sign_bytes) => {
                    let mut sign: Vec<u8> = Vec::new();

                    for c in image_sign_bytes {
                        if *c == 0 {
                            break;
                        } else {
                            sign.push(*c);
                        }
                    }

                    sign
                }
            },
        };

        // Sanity check
        if image_sign.is_empty() {
            debug!("No image sign");
            return Err(DecryptError::Input);
        }

        debug!("Trying {} keys", firmware.name);

        // Get the actual encrypted data
        if let Some(encrypted_data) = encrypted_image.get(firmware.encrypted_data_offset..) {
            // Generate possible keys for the given image_sign
            for crypto in keygen(&image_sign) {
                // Decrypt the encrypted data
                if let Ok(decrypted_data) =
                    aes_256_cbc_decrypt_unpadded(encrypted_data, &crypto.key, &crypto.iv)
                {
                    // Verify the decrypted magic bytes
                    if let Some(decrypted_magic) = decrypted_data.get(0..MAGIC_LEN) {
                        if known_decrypted_magics.contains(&decrypted_magic.to_vec()) {
                            debug!("Decryption OK");
                            return Ok(decrypted_data);
                        } else {
                            warn!("Decrypted magic bytes don't match");
                        }
                    }
                }
            }
        }
    }

    debug!("All decryption keys have failed");
    Err(DecryptError::Decrypt)
}

#[derive(Debug, Default, Clone)]
pub struct EncimgKey {
    pub iv: Vec<u8>,
    pub key: Vec<u8>,
}

/// Derive possible decryption keys from a given image_sign string
pub fn keygen(image_sign: &[u8]) -> Vec<EncimgKey> {
    const PROG_BOARD_LEN: usize = 0x80;

    const KEY_SEED_START: usize = 0x20;
    const KEY_SEED_END: usize = 0x40;

    const IV_SEED_START: usize = 0x60;
    const IV_SEED_END: usize = 0x70;

    // List of known prog_board_fw strings from various encimg releases.
    // Multiple devices may use the same prog_board_fw string.
    let prog_board_fws: Vec<Vec<u8>> = vec![
        // DAP-1665
        b"5gHW13MScSB4Xqqr8Mg8xl0zlQXCfykXEfCHXytwsC6F0zsedwZc+9vDbCjE3ge4Ts0682B35XQG\nP2tuxxuLMlvCJ266ZlnggPy917jwESpnfXmMiZRNcSviifjxTlg".to_vec(),
        // DIR-850L A1
        b"vzoLuJSCIFc3UwLZ6Is4Tyu95dFg9MssBIuS1CVMEQG+0pUeE99jnR+vLlLd9unrlvhwEvRdn99R\nEYmbe6y0HeABq/NtIXwf3+odwHhmJL1ceW16UsU3xgR7QH0CO9c".to_vec(),
        // DIR-850L B1
        b"k5NI1+bvWEfZ6ohtpUOwynOdUcivqwEZqQehHMEmEPQ5izL+cabn8bNHZXHjkp6WCl9yn9CIkiI1\nmTFu21TEEPo66JBFv9BMmb+IKQgnO8OuF4bz4frGPdN67gYLuOs".to_vec(),
        // DAP-2610
        b"db6zOuf7GJWGI64bm0DXpZ1rn4hFmPTxoVhq0hvXHdfaGFLdubM4/QvuVHdKee7vh6tC/sBL2t8h\n9GtlNghPDnf9wPrYOLk0BO5nlYankuVBe4sWaltHEHh7NToCSdq".to_vec(),
        // DIR-822
        b"2q02Oz+DDDKjLmMENiZN+3M8VucG4rYfKNpsEntCcsep1jdFIs3wnXySKRGNCGmfzYHzJEPD3GbX\ne/AF4zbvpjuPlmq58fHuph587JdKHrtAUlrli4/FkiKXBfDFbn2".to_vec(),
        // DIR-842
        b"XYWFilP+ZyydvsXAJSgKeF/p15q05g68xQYoRZeD726UAbRb846kO7TeNw8eZa6ucKxYrhxNbzjP\nbpgFJ7Yxa6sBeujdJ7fzufEbNF3kUafxFiESBRQI6qQbszYOvJI".to_vec(),
    ];

    let mut keys: Vec<EncimgKey> = Vec::new();

    for prog_board_fw in prog_board_fws {
        assert!(prog_board_fw.len() == PROG_BOARD_LEN);

        let iv_seed = &prog_board_fw[IV_SEED_START..IV_SEED_END];
        let key_seed = &prog_board_fw[KEY_SEED_START..KEY_SEED_END];

        keys.push(EncimgKey {
            iv: encrypt_xor(image_sign, iv_seed),
            key: encrypt_xor(image_sign, key_seed),
        });
    }

    keys
}

/// Same as the encrypt_xor function in the encimg binary
pub fn encrypt_xor(image_sign: &[u8], data: &[u8]) -> Vec<u8> {
    const MAX_XOR_BYTE: u8 = 0xFB;

    let mut xor_byte: u8 = 1;
    let mut image_sign_offset: usize = 0;
    let mut xor_data: Vec<u8> = Vec::new();

    for data_byte in data {
        xor_data.push(data_byte ^ xor_byte ^ image_sign[image_sign_offset]);

        xor_byte += 1;
        image_sign_offset += 1;

        if xor_byte > MAX_XOR_BYTE {
            xor_byte = 0;
        }

        if image_sign_offset >= image_sign.len() {
            image_sign_offset = 0;
        }
    }

    xor_data
}
