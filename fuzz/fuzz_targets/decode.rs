#![no_main]

extern crate bitcoin_encrypted_backup;
use bitcoin_encrypted_backup::ll::decode_v1;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|d: &[u8]| {
    let _ = decode_v1(d);
});
