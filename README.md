# DeLink

A crypto library to decrypt various encrypted D-Link firmware images.

Confirmed to work on the following D-Link devices:

* E15
* E30
* R12
* R15
* R18
* M18
* M30
* M32
* M60
* DAP-1665
* DAP-1820
* DAP-1955
* DAP-2610
* DAP-2680
* DAP-2682
* DIR-850L A1
* DIR-850L B1
* DAP-1610 B1
* DAP-1620 B1
* DAP-LX1880
* DRA-1360 A1
* DRA-2060 A1
* DIR-1750
* DIR-2055
* DIR-LX1870
* DIR-X1560
* DIR-X1870
* DIR-X4860
* DIR-X5460
* DIR-822
* DIR-842
* DIR-878
* DIR-2150
* DIR-3040
* DIR-3060

Encryption keys/methods are often re-used amongst devices and firmware, so other devices may also be supported.

## Compiling

You must have the Rust compiler installed:

```bash
cargo build --release
```

## Command Line Usage:

```bash
./target/release/delink encrypted.bin decrypted.bin
```

## Rust Library Usage:
```rust
// Read in the contents of an encrypted firmware image
match std::fs::read("DIR850LB1_FW220WWb03.bin") {
    Err(e) => {
        eprint!("Failed to read input file: {}", e);
    }
    Ok(encrypted_data) => {
        // Attempt to decrypt the encrypted data
        match delink::decrypt(&encrypted_data) {
            Err(e) => {
                eprint!("Decryption failed: {}", e);
            }
            Ok(decrypted_data) => {
                // Decryption successful, save decrypted data to disk
                if let Err(e) = std::fs::write("decrypted.bin", decrypted_data) {
                    eprint!("Failed to write decrypted data: {}", e);
                }
            }
        }
    }
}
```
