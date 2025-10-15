#![no_main]

extern crate bitcoin_encrypted_backup;
use bitcoin_encrypted_backup::{
    Content, Encryption, Version,
    ll::{
        decode_v1, encode_derivation_paths, encode_encrypted_payload, encode_individual_secrets,
        encode_v1, increment_offset, nonce, parse_derivation_paths, parse_individual_secrets,
    },
    miniscript::bitcoin::bip32::DerivationPath,
};

use libfuzzer_sys::fuzz_target;

fn version(bytes: &[u8]) -> (usize, Version) {
    if bytes.is_empty() {
        return (1, Version::Unknown);
    }
    (1, Version::from(bytes[0]))
}

fn content(bytes: &[u8]) -> (usize, Content) {
    if bytes.is_empty() {
        return (1, Content::Unknown);
    }
    (1, Content::from(bytes[0]))
}
fn encryption(bytes: &[u8]) -> (usize, Encryption) {
    if bytes.is_empty() {
        return (1, Encryption::Unknown);
    }
    (1, Encryption::from(bytes[0]))
}

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() < 5 {
        return;
    }
    let (mut offset, version) = version(bytes);
    if !version.is_valid() {
        return;
    }
    let (incr, deriv) = parse_derivation_paths(&bytes[offset..]).unwrap_or_default();
    offset = if let Ok(o) = increment_offset(bytes, offset, incr) {
        o
    } else {
        return;
    };
    let (incr, secrets) = parse_individual_secrets(&bytes[offset..]).unwrap_or_default();
    offset = if let Ok(o) = increment_offset(bytes, offset, incr) {
        o
    } else {
        return;
    };
    let (incr, content) = content(&bytes[offset..]);
    offset = if let Ok(o) = increment_offset(bytes, offset, incr) {
        o
    } else {
        return;
    };
    let (incr, encryption) = encryption(&bytes[offset..]);
    offset = if let Ok(o) = increment_offset(bytes, offset, incr) {
        o
    } else {
        return;
    };

    let deriv = encode_derivation_paths(deriv).unwrap();
    let secrets = if let Ok(is) = encode_individual_secrets(&secrets) {
        is
    } else {
        return;
    };

    let payload = encode_encrypted_payload(nonce(), "0".as_bytes()).unwrap();

    let bytes = encode_v1(
        version.into(),
        deriv,
        secrets,
        content.into(),
        encryption.into(),
        payload,
    );

    // println!("encoded: {bytes:?}");

    let _ = decode_v1(&bytes).unwrap();
});
