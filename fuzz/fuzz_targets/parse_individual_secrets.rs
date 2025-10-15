#![no_main]

use bitcoin_encrypted_backup::ll::parse_individual_secrets;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = parse_individual_secrets(bytes);
});
