#[cfg(feature = "miniscript_12_0")]
pub use mscript_12_0 as miniscript;
#[cfg(feature = "miniscript_12_3_5")]
pub use mscript_12_3_5 as miniscript;

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::{vec, vec::Vec};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use miniscript::bitcoin::{
    self,
    bip32::{ChildNumber, DerivationPath},
    hashes::{sha256, Hash, HashEngine},
    secp256k1, VarInt,
};
#[cfg(feature = "rand")]
use rand::{rngs::OsRng, TryRngCore};

use crate::{descriptor::bip341_nums, Encryption, Version};

const DECRYPTION_SECRET: &str = "BEB_BACKUP_DECRYPTION_SECRET";
const INDIVIDUAL_SECRET: &str = "BEB_BACKUP_INDIVIDUAL_SECRET";
const MAGIC: &str = "BEB";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    KeyCount,
    DerivPathCount,
    DerivPathLength,
    DerivPathEmpty,
    DataLength,
    Encrypt,
    Decrypt,
    Corrupted,
    Version,
    Magic,
    VarInt,
    WrongKey,
    IndividualSecretsEmpty,
    IndividualSecretsLength,
    CypherTextEmpty,
    CypherTextLength,
    ContentMetadata,
    Encryption,
    OffsetOverflow,
    EmptyBytes,
    Increment,
    ContentMetadataEmpty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    None,
    Bip380,
    Bip388,
    Bip329,
    BIP(u16),
    Proprietary(Vec<u8>),
    Unknown,
}

/// Encode content metadata, 3 variants:
/// - <LENGTH == 0> => None
/// - <LENGTH == 2><BIP_NUMBER> => encoding format defined in BIP<BIP_NUMBER>
/// - <LENGTH > 2> => proprietary
impl From<Content> for Vec<u8> {
    fn from(value: Content) -> Self {
        match value {
            Content::None => [0].into(),
            Content::Proprietary(mut data) => {
                assert!(data.len() > 2);
                assert!(data.len() < u8::MAX as usize);
                let mut content = vec![data.len() as u8];
                content.append(&mut data);
                content
            }
            Content::Unknown => unimplemented!(),
            c => {
                let mut content = vec![2];
                let bip_number = match c {
                    Content::Bip380 => 380u16.to_be_bytes(),
                    Content::Bip388 => 388u16.to_be_bytes(),
                    Content::Bip329 => 329u16.to_be_bytes(),
                    Content::BIP(bip) => bip.to_be_bytes(),
                    _ => unreachable!(),
                };
                content.append(&mut bip_number.to_vec());
                content
            }
        }
    }
}

pub fn parse_content_metadata(bytes: &[u8]) -> Result<(usize, Content), Error> {
    let len = bytes.len();
    if len == 0 {
        Err(Error::ContentMetadataEmpty)?
    }
    let data_len = bytes[0];
    match data_len {
        0 => Ok((1, Content::None)),
        1 => Err(Error::ContentMetadata),
        2 => {
            if bytes.len() < 3 {
                return Err(Error::ContentMetadata);
            }
            let bip_number = u16::from_be_bytes(bytes[1..3].try_into().expect("len ok"));
            match bip_number {
                380 => Ok((3, Content::Bip380)),
                388 => Ok((3, Content::Bip388)),
                329 => Ok((3, Content::Bip329)),
                bip_number => Ok((3, Content::BIP(bip_number))),
            }
        }
        len => {
            if bytes.len() < (len as usize + 1) {
                return Err(Error::ContentMetadata);
            }
            let end = (len as usize + 1).min(bytes.len());
            let data = &bytes[1..end].to_vec();
            Ok((end, Content::Proprietary(data.to_vec())))
        }
    }
}

impl Content {
    pub fn is_known(&self) -> bool {
        match self {
            Content::None | Content::Unknown | Content::Proprietary(_) => false,
            Content::Bip380 | Content::Bip388 | Content::Bip329 | Content::BIP(_) => true,
        }
    }
}

pub fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[cfg(feature = "rand")]
pub fn nonce() -> [u8; 12] {
    let mut rng = OsRng;
    let mut nonce = [0u8; 12];
    rng.try_fill_bytes(&mut nonce)
        .expect("os rng must not fail");
    nonce
}

pub fn decryption_secret(keys: &[[u8; 33]]) -> sha256::Hash {
    let mut engine = sha256::HashEngine::default();
    engine.input(DECRYPTION_SECRET.as_bytes());
    keys.iter().for_each(|k| engine.input(k));
    sha256::Hash::from_engine(engine)
}

pub fn individual_secret(secret: &sha256::Hash, key: &[u8; 33]) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    engine.input(INDIVIDUAL_SECRET.as_bytes());
    engine.input(key);
    let si = sha256::Hash::from_engine(engine);
    xor(secret.as_byte_array(), si.as_byte_array())
}

pub fn individual_secrets(secret: &sha256::Hash, keys: &[[u8; 33]]) -> Vec<[u8; 32]> {
    keys.iter()
        .map(|k| individual_secret(secret, k))
        .collect::<Vec<_>>()
}

pub fn inner_encrypt(
    secret: sha256::Hash,
    mut data: Vec<u8>,
    #[cfg(not(feature = "rand"))] nonce: [u8; 12],
) -> Result<([u8; 12], Vec<u8>), Error> {
    #[cfg(feature = "rand")]
    let nonce = nonce();

    #[allow(deprecated)]
    let key = Key::<Aes256Gcm>::from_slice(secret.as_byte_array());
    let cipher = Aes256Gcm::new(key);

    let mut plaintext = vec![];
    plaintext.append(&mut data);

    cipher
        .encrypt(&Nonce::from(nonce), plaintext.as_slice())
        .map(|c| (nonce, c))
        .map_err(|_| Error::Encrypt)
}

/// Encode following this format:
/// <LENGTH><DERIVATION_PATH_1><DERIVATION_PATH_2><..><DERIVATION_PATH_N>
pub fn encode_derivation_paths(derivation_paths: Vec<DerivationPath>) -> Result<Vec<u8>, Error> {
    if derivation_paths.len() > u8::MAX as usize {
        return Err(Error::DerivPathLength);
    }
    let mut encoded_paths = vec![derivation_paths.len() as u8];
    for path in derivation_paths {
        let childs = path.to_u32_vec();
        let len = childs.len();
        if len > u8::MAX as usize {
            return Err(Error::DerivPathLength);
        }
        encoded_paths.push(len as u8);
        for c in childs {
            encoded_paths.append(&mut c.to_be_bytes().to_vec());
        }
    }
    Ok(encoded_paths)
}

/// Encode following this format:
/// <LENGTH><INDIVIDUAL_SECRET_1><INDIVIDUAL_SECRET_2><..><INDIVIDUAL_SECRET_N>
pub fn encode_individual_secrets(individual_secrets: &[[u8; 32]]) -> Result<Vec<u8>, Error> {
    let individual_secrets: BTreeSet<_> = individual_secrets.iter().collect();
    if individual_secrets.len() > u8::MAX as usize {
        return Err(Error::IndividualSecretsLength);
    } else if individual_secrets.is_empty() {
        return Err(Error::IndividualSecretsEmpty);
    }
    let len = individual_secrets.len() as u8;
    let mut out = Vec::with_capacity(1 + (individual_secrets.len() * 32));
    out.push(len);
    for is in individual_secrets {
        out.append(&mut is.to_vec());
    }
    Ok(out)
}

/// Encode following this format:
/// <NONCE><LENGTH><CYPHERTEXT>
pub fn encode_encrypted_payload(nonce: [u8; 12], cyphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if cyphertext.is_empty() {
        return Err(Error::CypherTextEmpty);
    }
    let mut out = Vec::new();
    out.append(&mut nonce.as_slice().to_vec());
    let mut var_int = bitcoin::consensus::serialize(&bitcoin::VarInt(cyphertext.len() as u64));
    out.append(&mut var_int);
    out.append(&mut cyphertext.to_vec());

    Ok(out)
}

/// Encode following this format
/// <MAGIC><VERSION><DERIVATION_PATHS><INDIVIDUAL_SECRETS><ENCRYPTION><ENCRYPTED_PAYLOAD>
/// NOTE: payload that will fail to decode can be encoded with this function, for instance with an
/// invalid version, the inputs args must be sanitized by the caller.
pub fn encode_v1(
    version: u8,
    mut derivation_paths: Vec<u8>,
    mut individual_secrets: Vec<u8>,
    encryption: u8,
    mut encrypted_payload: Vec<u8>,
) -> Vec<u8> {
    // <MAGIC>
    let mut out = MAGIC.as_bytes().to_vec();
    // <VERSION>
    out.push(version);
    // <DERIVATION_PATHS>
    out.append(&mut derivation_paths);
    // <INDIVIDUAL_SECRETS>
    out.append(&mut individual_secrets);
    // <ENCRYPTION>
    out.push(encryption);
    // <ENCRYPTED_PAYLOAD>
    out.append(&mut encrypted_payload);
    out
}

pub fn check_offset(offset: usize, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() <= offset {
        Err(Error::Corrupted)
    } else {
        Ok(())
    }
}

pub fn check_offset_lookahead(offset: usize, bytes: &[u8], lookahead: usize) -> Result<(), Error> {
    let target = offset
        .checked_add(lookahead)
        .ok_or(Error::Increment)?
        .checked_sub(1)
        .ok_or(Error::Increment)?;
    if bytes.len() <= target {
        Err(Error::Corrupted)
    } else {
        Ok(())
    }
}

pub fn init_offset(bytes: &[u8], value: usize) -> Result<usize, Error> {
    check_offset(value, bytes)?;
    Ok(value)
}

pub fn increment_offset(bytes: &[u8], offset: usize, incr: usize) -> Result<usize, Error> {
    check_offset(offset + incr, bytes)?;
    offset.checked_add(incr).ok_or(Error::OffsetOverflow)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><..>
pub fn decode_version(bytes: &[u8]) -> Result<u8, Error> {
    // <MAGIC>
    let offset = init_offset(bytes, parse_magic_byte(bytes)?)?;
    // <VERSION>
    let (_, version) = parse_version(&bytes[offset..])?;
    Ok(version)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><DERIVATION_PATHS><..>
pub fn decode_derivation_paths(bytes: &[u8]) -> Result<Vec<DerivationPath>, Error> {
    // <MAGIC>
    let mut offset = init_offset(bytes, parse_magic_byte(bytes)?)?;
    // <VERSION>
    let (incr, _) = parse_version(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <DERIVATION_PATHS>
    let (_, derivation_paths) = parse_derivation_paths(&bytes[offset..])?;
    Ok(derivation_paths)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><DERIVATION_PATHS><INDIVIDUAL_SECRETS><ENCRYPTION><ENCRYPTED_PAYLOAD><..>
#[allow(clippy::type_complexity)]
pub fn decode_v1(
    bytes: &[u8],
) -> Result<
    (
        Vec<DerivationPath>, /* derivation_paths */
        Vec<[u8; 32]>,       /* individual_secrets */
        u8,                  /* encryption_type */
        [u8; 12],            /* nonce */
        Vec<u8>,             /* cyphertext */
    ),
    Error,
> {
    // <MAGIC>
    let mut offset = init_offset(bytes, parse_magic_byte(bytes)?)?;
    // <VERSION>
    let (incr, _) = parse_version(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <DERIVATION_PATHS>
    let (incr, derivation_paths) = parse_derivation_paths(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <INDIVIDUAL_SECRETS>
    let (incr, individual_secrets) = parse_individual_secrets(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <ENCRYPTION>
    let (incr, encryption_type) = parse_encryption(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <ENCRYPTED_PAYLOAD>
    let (nonce, cyphertext) = parse_encrypted_payload(&bytes[offset..])?;

    Ok((
        derivation_paths,
        individual_secrets,
        encryption_type,
        nonce,
        cyphertext,
    ))
}

pub fn encrypt_aes_gcm_256_v1(
    derivation_paths: Vec<DerivationPath>,
    content_metadata: Content,
    keys: Vec<secp256k1::PublicKey>,
    data: &[u8],
    #[cfg(not(feature = "rand"))] nonce: [u8; 12],
) -> Result<Vec<u8>, Error> {
    // drop duplicates keys and sort out bip341 nums
    let keys = keys
        .into_iter()
        .filter(|k| *k != bip341_nums())
        .collect::<BTreeSet<_>>();

    // drop duplicates derivation paths
    let derivation_paths = derivation_paths
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if keys.len() > u8::MAX as usize || keys.is_empty() {
        return Err(Error::KeyCount);
    }
    if derivation_paths.len() > u8::MAX as usize {
        return Err(Error::DerivPathCount);
    }
    // NOTE:  RFC5116 define the max length of the plaintext to 2^36 - 31
    // but for convenience we limit it to u32::MAX in order to not exceed
    // usize::MAX on 32 bits architectures
    // https://datatracker.ietf.org/doc/html/rfc5116#section-5.1
    if data.len() > u32::MAX as usize {
        return Err(Error::DataLength);
    }
    if data.is_empty() {
        return Err(Error::DataLength);
    }

    let content_metadata: Vec<u8> = content_metadata.into();
    if content_metadata.is_empty() {
        return Err(Error::ContentMetadata);
    }

    let mut raw_keys = keys.into_iter().map(|k| k.serialize()).collect::<Vec<_>>();
    raw_keys.sort();

    let secret = decryption_secret(&raw_keys);
    let individual_secrets =
        encode_individual_secrets(&individual_secrets(&secret, raw_keys.as_slice()))?;
    let derivation_paths = encode_derivation_paths(derivation_paths)?;

    // <PAYLOAD> = <CONTENT_METADATA><DATA>
    let mut payload = content_metadata;
    payload.append(&mut data.to_vec());

    let (nonce, cyphertext) = inner_encrypt(
        secret,
        payload.to_vec(),
        #[cfg(not(feature = "rand"))]
        nonce,
    )?;
    let encrypted_payload = encode_encrypted_payload(nonce, cyphertext.as_slice())?;

    Ok(encode_v1(
        Version::V1.into(),
        derivation_paths,
        individual_secrets,
        Encryption::AesGcm256.into(),
        encrypted_payload,
    ))
}

pub fn try_decrypt_aes_gcm_256(
    cyphertext: &[u8],
    secret: &[u8; 32],
    nonce: [u8; 12],
) -> Option<Vec<u8>> {
    let nonce = Nonce::from(nonce);

    #[allow(deprecated)]
    let key = Key::<Aes256Gcm>::from_slice(secret);
    let cipher = Aes256Gcm::new(key);

    cipher.decrypt(&nonce, cyphertext).ok()
}

pub fn decrypt_aes_gcm_256_v1(
    key: secp256k1::PublicKey,
    individual_secrets: &Vec<[u8; 32]>,
    cyphertext: Vec<u8>,
    nonce: [u8; 12],
) -> Result<(Content, Vec<u8>), Error> {
    let raw_key = key.serialize();

    let mut engine = sha256::HashEngine::default();
    engine.input(INDIVIDUAL_SECRET.as_bytes());
    engine.input(&raw_key);
    let si = sha256::Hash::from_engine(engine);

    for ci in individual_secrets {
        let secret = xor(si.as_byte_array(), ci);
        if let Some(out) = try_decrypt_aes_gcm_256(&cyphertext, &secret, nonce) {
            let mut offset = init_offset(&out, 0)?;
            // <CONTENT_METADATA>
            let (incr, content) = parse_content_metadata(&out)?;
            // <DECRYPTED_PAYLOAD>
            offset = increment_offset(&out, offset, incr)?;
            let out = out[offset..].to_vec();
            return Ok((content, out));
        }
    }

    Err(Error::WrongKey)
}

pub fn parse_magic_byte(bytes: &[u8]) -> Result<usize /* offset */, Error> {
    let magic = MAGIC.as_bytes();

    if bytes.len() < magic.len() || &bytes[..magic.len()] != magic {
        return Err(Error::Magic);
    }
    Ok(magic.len())
}

pub fn parse_version(bytes: &[u8]) -> Result<(usize, u8), Error> {
    if bytes.is_empty() {
        return Err(Error::Version);
    }
    let version = bytes[0];
    if version > Version::max().into() {
        return Err(Error::Version);
    }
    Ok((1, version))
}

pub fn parse_encryption(bytes: &[u8]) -> Result<(usize, u8), Error> {
    if bytes.is_empty() {
        return Err(Error::Encryption);
    }
    let encryption = bytes[0];
    Ok((1, encryption))
}

/// Expects to parse a payload of the form:
/// <COUNT>
/// <CHILD_COUNT><CHILD><..><CHILD>
/// <..>
/// <CHILD_COUNT><CHILD><..><CHILD>
/// <..>
pub fn parse_derivation_paths(
    bytes: &[u8],
) -> Result<(usize /* offset */, Vec<DerivationPath>), Error> {
    let mut offset = init_offset(bytes, 0).map_err(|_| Error::DerivPathEmpty)?;
    let mut derivation_paths = BTreeSet::new();

    // <COUNT>
    let count = bytes[0];

    if count != 0 {
        offset = increment_offset(bytes, offset, 1)?;
        for _ in 0..count {
            check_offset(offset, bytes)?;
            // <CHILD_COUNT>
            let child_count = bytes[offset];
            if child_count == 0 {
                return Err(Error::DerivPathEmpty);
            } else {
                let mut childs = vec![];
                offset += 1;
                for _ in 0..child_count {
                    check_offset_lookahead(offset, bytes, 4)?;
                    // <CHILD>
                    let raw_child: [u8; 4] =
                        bytes[offset..(offset + 4)].try_into().expect("verified");
                    let child = u32::from_be_bytes(raw_child);
                    let child = ChildNumber::from(child);
                    childs.push(child);
                    offset += 4;
                }
                derivation_paths.insert(DerivationPath::from(childs));
            }
        }
    } else {
        offset += 1;
    }

    let derivation_paths = derivation_paths.into_iter().collect();

    Ok((offset, derivation_paths))
}

/// Expects to parse a payload of the form:
/// <COUNT>
/// <INDIVIDUAL_SECRET>
/// <..>
/// <INDIVIDUAL_SECRET>
/// <..>
pub fn parse_individual_secrets(
    bytes: &[u8],
) -> Result<(usize /* offset */, Vec<[u8; 32]>), Error> {
    if bytes.is_empty() {
        return Err(Error::EmptyBytes);
    }
    // <COUNT>
    let count = bytes[0];
    if count < 1 {
        return Err(Error::IndividualSecretsEmpty);
    }
    let mut offset = init_offset(bytes, 1)?;

    let mut individual_secrets = BTreeSet::new();
    for _ in 0..count {
        check_offset_lookahead(offset, bytes, 32)?;
        // <INDIVIDUAL_SECRET>
        let secret: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| Error::Corrupted)?;
        individual_secrets.insert(secret);
        offset += 32;
    }

    let individual_secrets = individual_secrets.into_iter().collect();
    Ok((offset, individual_secrets))
}

/// Expects to parse a payload of the form:
/// <NONCE><LENGTH><CYPHERTEXT>
/// <..>
pub fn parse_encrypted_payload(
    bytes: &[u8],
) -> Result<([u8; 12] /* nonce */, Vec<u8> /* cyphertext */), Error> {
    let mut offset = init_offset(bytes, 0)?;
    // <NONCE>
    check_offset_lookahead(offset, bytes, 12)?;
    let nonce: [u8; 12] = bytes[offset..offset + 12].try_into().expect("checked");
    offset = increment_offset(bytes, offset, 12)?;
    // <LENGTH>
    let (VarInt(data_len), incr) =
        bitcoin::consensus::deserialize_partial(&bytes[offset..]).map_err(|_| Error::VarInt)?;
    // FIXME: in 32bit systems usize is 32 bits
    let data_len = data_len as usize;
    offset = increment_offset(bytes, offset, incr)?;
    // <CYPHERTEXT>
    check_offset_lookahead(offset, bytes, data_len)?;
    let cyphertext = bytes[offset..offset + data_len].to_vec();
    Ok((nonce, cyphertext))
}

#[cfg(all(test, feature = "rand"))]
mod tests {
    use alloc::string::{String, ToString};
    use core::str::FromStr;
    use miniscript::bitcoin::XOnlyPublicKey;
    use rand::random;

    use super::*;

    fn pk1() -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_str(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
        )
        .unwrap()
    }

    fn pk2() -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_str(
            "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07",
        )
        .unwrap()
    }

    fn pk3() -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_str(
            "0384526253c27c7aef56c7b71a5cd25bebb000000a437826defc5b2568bde81f07",
        )
        .unwrap()
    }

    #[test]
    fn test_fuzz_catch_1() {
        // NOTE: the bug was in check_offset_lookahead() where substract 1 to 0 panics
        let bytes = [
            66, 73, 80, 88, 88, 88, 88, 0, 0, 1, 0, 0, 0, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 207, 207, 207, 207, 207, 207, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            32, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 0, 0, 0, 185, 185, 0, 88, 0, 0, 185, 185,
        ];
        let _ = decode_v1(&bytes);
    }

    #[test]
    fn test_nonce() {
        let nonce_1 = nonce();
        let nonce_2 = nonce();
        assert_ne!(nonce_1, nonce_2);
    }

    #[test]
    fn test_check_offset() {
        let res = check_offset(1, &[0x00]);
        assert!(res.is_err());
        check_offset(1, &[0x00, 0x00]).unwrap();
    }

    #[test]
    fn test_check_offset_look_ahead() {
        let res = check_offset_lookahead(0, &[0x00; 2], 3);
        assert!(res.is_err());
        check_offset_lookahead(0, &[0x00; 2], 2).unwrap();
    }

    #[test]
    fn test_init_offset() {
        let res = init_offset(&[0x00], 1);
        assert!(res.is_err());
        init_offset(&[0x00], 0).unwrap();
    }

    #[test]
    fn test_increment_offset() {
        let res = increment_offset(&[0x00], 0, 1);
        assert!(res.is_err());
        increment_offset(&[0x00; 2], 0, 1).unwrap();
    }

    #[test]
    fn test_parse_magic() {
        let magic = "BEB".as_bytes();
        assert_eq!(MAGIC, "BEB");
        let offset = parse_magic_byte(magic).unwrap();
        assert_eq!(offset, magic.len());
        let res = parse_magic_byte("BOBt s".as_bytes());
        assert_eq!(res, Err(Error::Magic));
        let _ = parse_magic_byte(MAGIC.as_bytes()).unwrap();
    }

    #[test]
    fn test_parse_version() {
        let (_, v) = parse_version(&[0x00]).unwrap();
        assert_eq!(v, 0x00);
        let (_, v) = parse_version(&[0x01]).unwrap();
        assert_eq!(v, 0x01);
        let res = parse_version(&[]);
        assert_eq!(res, Err(Error::Version));
        let res = parse_version(&[0x02]);
        assert_eq!(res, Err(Error::Version));
    }

    #[test]
    pub fn test_parse_encryption() {
        let (l, e) = parse_encryption(&[0]).unwrap();
        assert_eq!(l, 1);
        assert_eq!(e, 0);
        let (l, e) = parse_encryption(&[0, 2]).unwrap();
        assert_eq!(l, 1);
        assert_eq!(e, 0);
        let (l, e) = parse_encryption(&[2, 0]).unwrap();
        assert_eq!(l, 1);
        assert_eq!(e, 2);
        let failed = parse_encryption(&[]).unwrap_err();
        assert_eq!(failed, Error::Encryption)
    }

    #[test]
    pub fn test_parse_derivation_path() {
        // single deriv path
        let (_, p) = parse_derivation_paths(&[0x01, 0x01, 0x00, 0x00, 0x00, 0x01]).unwrap();
        assert_eq!(p.len(), 1);

        // child number must be encoded on 4 bytes
        let p = parse_derivation_paths(&[0x01, 0x01, 0x00]).unwrap_err();
        assert_eq!(p, Error::Corrupted);
        let p = parse_derivation_paths(&[0x01, 0x01, 0x00, 0x00]).unwrap_err();
        assert_eq!(p, Error::Corrupted);
        let p = parse_derivation_paths(&[0x01, 0x01, 0x00, 0x00, 0x00]).unwrap_err();
        assert_eq!(p, Error::Corrupted);

        // empty childs
        let p = parse_derivation_paths(&[0x01, 0x00]).unwrap_err();
        assert_eq!(p, Error::DerivPathEmpty);
    }

    #[test]
    pub fn test_parse_individual_secrets() {
        // empty bytes
        let fail = parse_individual_secrets(&[]).unwrap_err();
        assert_eq!(fail, Error::EmptyBytes);

        // empty vector
        let fail = parse_individual_secrets(&[0x00]).unwrap_err();
        assert_eq!(fail, Error::IndividualSecretsEmpty);

        let is1 = [1u8; 32].to_vec();
        let is2 = [2u8; 32].to_vec();

        // single secret
        let mut bytes = vec![0x01];
        bytes.append(&mut is1.clone());
        let (_, is) = parse_individual_secrets(&bytes).unwrap();
        assert_eq!(is[0].to_vec(), is1);

        // multiple secrets
        let mut bytes = vec![0x02];
        bytes.append(&mut is1.clone());
        bytes.append(&mut is2.clone());
        let (_, is) = parse_individual_secrets(&bytes).unwrap();
        assert_eq!(is[0].to_vec(), is1);
        assert_eq!(is[1].to_vec(), is2);
    }

    #[test]
    fn test_parse_content() {
        // empty bytes must fail
        assert!(parse_content_metadata(&[]).is_err());
        // None
        let (_, c) = parse_content_metadata(&[0]).unwrap();
        assert_eq!(c, Content::None);
        // len == 1 fails
        assert!(parse_content_metadata(&[1, 0]).is_err());
        // BIP380
        let (_, c) = parse_content_metadata(&[2, 0x01, 0x7c]).unwrap();
        assert_eq!(c, Content::Bip380);
        // BIP388
        let (_, c) = parse_content_metadata(&[2, 0x01, 0x84]).unwrap();
        assert_eq!(c, Content::Bip388);
        // BIP329
        let (_, c) = parse_content_metadata(&[2, 0x01, 0x49]).unwrap();
        assert_eq!(c, Content::Bip329);
        // Arbitrary BIPs
        let (_, c) = parse_content_metadata(&[2, 0xFF, 0xFF]).unwrap();
        assert_eq!(c, Content::BIP(u16::MAX));
        let (_, c) = parse_content_metadata(&[2, 0, 0]).unwrap();
        assert_eq!(c, Content::BIP(0));
        // Proprietary
        let (_, c) = parse_content_metadata(&[3, 0, 0, 0]).unwrap();
        assert_eq!(c, Content::Proprietary(vec![0, 0, 0]));
    }

    #[test]
    fn test_parse_content_metadata_insufficient_bytes() {
        // LENGTH=2 but only 1 byte follows (should need 2 bytes for BIP number)
        let result = parse_content_metadata(&[2, 0x01]);
        assert_eq!(result, Err(Error::ContentMetadata));

        // LENGTH=3 but only 2 bytes follow (should need 3 bytes for proprietary)
        let result = parse_content_metadata(&[3, 0xAA, 0xBB]);
        assert_eq!(result, Err(Error::ContentMetadata));

        // LENGTH=5 but only 3 bytes follow
        let result = parse_content_metadata(&[5, 0xAA, 0xBB, 0xCC]);
        assert_eq!(result, Err(Error::ContentMetadata));

        // Edge case: LENGTH=255 (reserved) but even if it weren't, insufficient bytes
        let result = parse_content_metadata(&[255, 0xAA]);
        assert_eq!(result, Err(Error::ContentMetadata));
    }

    #[test]
    fn test_parse_content_metadata_exact_bytes() {
        // LENGTH=3 with exactly 3 bytes - should succeed
        let (offset, content) = parse_content_metadata(&[3, 0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(offset, 4); // 1 (LENGTH) + 3 (data)
        assert_eq!(content, Content::Proprietary(vec![0xAA, 0xBB, 0xCC]));

        // LENGTH=2 with exactly 2 bytes - should succeed for BIP number
        let (offset, content) = parse_content_metadata(&[2, 0x01, 0x7C]).unwrap();
        assert_eq!(offset, 3);
        assert_eq!(content, Content::Bip380);
    }

    #[test]
    fn test_serialize_content() {
        // Proprietary
        let mut c = Content::Proprietary(vec![0, 0, 0]);
        let mut serialized: Vec<u8> = c.into();
        assert_eq!(serialized, vec![3, 0, 0, 0]);
        // BIP 380
        c = Content::Bip380;
        serialized = c.into();
        assert_eq!(serialized, vec![0x02, 0x01, 0x7C]);
        c = Content::BIP(380);
        serialized = c.into();
        assert_eq!(serialized, vec![0x02, 0x01, 0x7C]);
        // BIP 388
        c = Content::Bip388;
        serialized = c.into();
        assert_eq!(serialized, vec![0x02, 0x01, 0x84]);
        c = Content::BIP(388);
        serialized = c.into();
        assert_eq!(serialized, vec![0x02, 0x01, 0x84]);
        // BIP 329
        c = Content::Bip329;
        serialized = c.into();
        assert_eq!(serialized, vec![0x02, 0x01, 0x49]);
        c = Content::BIP(329);
        serialized = c.into();
        assert_eq!(serialized, vec![0x02, 0x01, 0x49]);
    }

    #[test]
    fn test_content_is_known() {
        let mut c = Content::None;
        assert!(!c.is_known());
        c = Content::Unknown;
        assert!(!c.is_known());
        c = Content::Proprietary(vec![0, 0, 0]);
        assert!(!c.is_known());
        c = Content::Bip380;
        assert!(c.is_known());
        c = Content::Bip388;
        assert!(c.is_known());
        c = Content::Bip329;
        assert!(c.is_known());
        c = Content::BIP(0);
        assert!(c.is_known());
    }

    #[test]
    fn test_simple_encode_decode_encrypted_payload() {
        let bytes = encode_encrypted_payload([3; 12], &[1, 2, 3, 4]).unwrap();
        let mut expected = [3; 12].to_vec();
        expected.append(&mut [4, 1, 2, 3, 4].to_vec());
        assert_eq!(bytes, expected);
        let (nonce, cyphertext) = parse_encrypted_payload(&bytes).unwrap();
        assert_eq!([3u8; 12], nonce);
        assert_eq!([1, 2, 3, 4].to_vec(), cyphertext);
    }

    #[test]
    fn test_encode_empty_encrypted_payload() {
        let res = encode_encrypted_payload([3; 12], &[]);
        assert_eq!(res, Err(Error::CypherTextEmpty));
    }

    #[test]
    fn test_encode_decode_derivation_paths() {
        let bytes = encode_derivation_paths(vec![
            DerivationPath::from_str("0/1h/2/3h").unwrap(),
            DerivationPath::from_str("84'/0'/0'/2'").unwrap(),
        ])
        .unwrap();
        let expected = vec![
            2, 4, 0, 0, 0, 0, 128, 0, 0, 1, 0, 0, 0, 2, 128, 0, 0, 3, 4, 128, 0, 0, 84, 128, 0, 0,
            0, 128, 0, 0, 0, 128, 0, 0, 2,
        ];
        assert_eq!(expected, bytes);
        let (offset, paths) = parse_derivation_paths(&bytes).unwrap();
        assert_eq!(offset, 35);
        assert_eq!(
            paths,
            vec![
                DerivationPath::from_str("0/1h/2/3h").unwrap(),
                DerivationPath::from_str("84'/0'/0'/2'").unwrap(),
            ]
        );
    }

    #[test]
    fn test_decode_deriv_path_sorted() {
        let bytes = encode_derivation_paths(vec![
            DerivationPath::from_str("84'/0'/0'/2'").unwrap(),
            DerivationPath::from_str("0/1h/2/3h").unwrap(),
        ])
        .unwrap();
        let (_, paths) = parse_derivation_paths(&bytes).unwrap();
        assert_eq!(
            paths,
            // NOTE: order of derivation paths is reverted here as during parsing they are stored
            // in an BTreeSet in order to avoid duplicates
            vec![
                DerivationPath::from_str("0/1h/2/3h").unwrap(),
                DerivationPath::from_str("84'/0'/0'/2'").unwrap(),
            ]
        );
    }

    #[test]
    fn test_decode_deriv_path_no_duplicates() {
        let bytes = encode_derivation_paths(vec![
            DerivationPath::from_str("0/1h/2/3h").unwrap(),
            DerivationPath::from_str("84'/0'/0'/2'").unwrap(),
            DerivationPath::from_str("84'/0'/0'/2'").unwrap(),
        ])
        .unwrap();
        let (_, paths) = parse_derivation_paths(&bytes).unwrap();
        assert_eq!(
            paths,
            vec![
                DerivationPath::from_str("0/1h/2/3h").unwrap(),
                DerivationPath::from_str("84'/0'/0'/2'").unwrap(),
            ]
        );
    }

    #[test]
    fn test_decode_deriv_path_empty() {
        let bytes = encode_derivation_paths(vec![]).unwrap();
        assert_eq!(bytes, vec![0x00]);
        let (_, paths) = parse_derivation_paths(&bytes).unwrap();
        assert_eq!(paths, vec![]);
    }

    #[test]
    fn test_encode_too_much_deriv_paths() {
        let mut deriv_paths = vec![];
        for _ in 0..256 {
            deriv_paths.push(DerivationPath::from_str("0/1h/2/3h").unwrap());
        }
        assert_eq!(deriv_paths.len(), 256);
        let res = encode_derivation_paths(deriv_paths);
        assert_eq!(res, Err(Error::DerivPathLength));
    }

    #[test]
    fn test_encode_too_long_deriv_paths() {
        let mut deriv_path = vec![];
        for _ in 0..256 {
            deriv_path.push(ChildNumber::from_normal_idx(0).unwrap());
        }
        assert_eq!(deriv_path.len(), 256);
        let res = encode_derivation_paths(vec![DerivationPath::from(deriv_path)]);
        assert_eq!(res, Err(Error::DerivPathLength));
    }

    #[test]
    fn test_encode_decode_encrypted_payload() {
        let payloads = [
            "test".as_bytes().to_vec(),
            [1; 0x1FFF].to_vec(),
            [2; 0x2FFFFFFF].to_vec(),
        ];
        for payload in payloads {
            let bytes = encode_encrypted_payload([3; 12], &payload).unwrap();
            let (nonce, cyphertext) = parse_encrypted_payload(&bytes).unwrap();
            assert_eq!([3u8; 12], nonce);
            assert_eq!(payload, cyphertext);
        }
    }

    #[test]
    fn test_encode_empty_individual_secrets() {
        let res = encode_individual_secrets(&[]);
        assert_eq!(res, Err(Error::IndividualSecretsEmpty));
    }

    #[test]
    fn test_too_much_individual_secrets() {
        let mut secrets = vec![];
        let mut rng = OsRng;
        for _ in 0..256 {
            let mut secret = [0u8; 32];
            rng.try_fill_bytes(&mut secret).unwrap();
            secrets.push(secret);
        }
        let res = encode_individual_secrets(&secrets);
        assert_eq!(res, Err(Error::IndividualSecretsLength));
    }

    #[test]
    fn test_encode_decode_individual_secrets() {
        let secrets = vec![[0; 32], [1; 32]];
        let bytes = encode_individual_secrets(&secrets).unwrap();
        let expected = vec![
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
        ];
        assert_eq!(expected, bytes);
        let (_, decoded) = parse_individual_secrets(&bytes).unwrap();
        assert_eq!(secrets, decoded);
    }

    #[test]
    fn test_encode_individual_secrets_no_duplicates() {
        let secrets = vec![[0; 32], [0; 32]];
        let bytes = encode_individual_secrets(&secrets).unwrap();
        let expected = vec![
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        assert_eq!(expected, bytes);
    }

    #[test]
    fn test_decode_individual_secrets_no_duplicates() {
        let bytes = vec![
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (_, secrets) = parse_individual_secrets(&bytes).unwrap();
        assert_eq!(secrets.len(), 1);
    }

    #[test]
    fn test_encode_decode_v1() {
        let bytes = encode_v1(
            0x01,
            encode_derivation_paths(vec![DerivationPath::from_str("8/9").unwrap()]).unwrap(),
            [0x01; 33].to_vec(),
            0x01,
            encode_encrypted_payload([0x04u8; 12], &[0x00]).unwrap(),
        );
        // <MAGIC>
        let mut expected = MAGIC.as_bytes().to_vec();
        // <VERSION>
        expected.append(&mut vec![0x01]);
        // <DERIVATION_PATHS>
        expected.append(&mut vec![
            0x01, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x09,
        ]);
        // <INDIVIDUAL_SECRETS>
        expected.append(&mut [0x01; 33].to_vec());
        // <ENCRYPTION>
        expected.append(&mut vec![0x01]);
        // <ENCRYPTED_PAYLOAD>
        expected.append(&mut encode_encrypted_payload([0x04u8; 12], &[0x00]).unwrap());
        assert_eq!(bytes, expected);
        let version = decode_version(&bytes).unwrap();
        assert_eq!(version, 0x01);
        let derivs = decode_derivation_paths(&bytes).unwrap();
        assert_eq!(derivs, vec![DerivationPath::from_str("8/9").unwrap()]);
        let (derivs, secrets, encryption, nonce, cyphertext) = decode_v1(&bytes).unwrap();
        assert_eq!(derivs, vec![DerivationPath::from_str("8/9").unwrap()]);
        assert_eq!(secrets, vec![[0x01; 32]]);
        assert_eq!(encryption, 0x01);
        assert_eq!(nonce, [0x04u8; 12]);
        assert_eq!(cyphertext, vec![0x00]);
    }

    #[test]
    fn test_encrypt_sanitizing() {
        // Empty keyvector must fail
        let keys = vec![];
        let data = "test".as_bytes().to_vec();
        let res = encrypt_aes_gcm_256_v1(vec![], Content::Bip380, keys, &data);
        assert_eq!(res, Err(Error::KeyCount));

        // > 255 keys must fail
        let mut keys = BTreeSet::new();
        while keys.len() < 256 {
            let key: [u8; 32] = random();
            if let Ok(k) = XOnlyPublicKey::from_slice(&key) {
                let k = bitcoin::secp256k1::PublicKey::from_x_only_public_key(
                    k,
                    secp256k1::Parity::Odd,
                );
                keys.insert(k);
            }
        }
        let keys = keys.into_iter().collect::<Vec<_>>();
        let res = encrypt_aes_gcm_256_v1(vec![], Content::Bip380, keys, &data);
        assert_eq!(res, Err(Error::KeyCount));

        // Empty payload must fail
        let keys = [pk1()].to_vec();
        let res = encrypt_aes_gcm_256_v1(vec![], Content::Bip380, keys, &[]);
        assert_eq!(res, Err(Error::DataLength));

        // > 255 deriv path must fail
        let keys = [pk1()].to_vec();
        let mut deriv_paths = BTreeSet::new();
        while deriv_paths.len() < 256 {
            let raw_deriv: [u32; 4] = random();
            let childs: Vec<ChildNumber> =
                raw_deriv.iter().copied().map(ChildNumber::from).collect();
            let deriv: DerivationPath = childs.into();
            deriv_paths.insert(deriv);
        }
        let deriv_paths = deriv_paths.into_iter().collect();
        let res = encrypt_aes_gcm_256_v1(deriv_paths, Content::Bip380, keys, &data);
        assert_eq!(res, Err(Error::DerivPathCount));
    }

    #[test]
    fn test_basic_encrypt_decrypt() {
        let keys = vec![pk2(), pk1()];
        let data = "test".as_bytes().to_vec();
        let bytes = encrypt_aes_gcm_256_v1(vec![], Content::None, keys, &data).unwrap();

        let version = decode_version(&bytes).unwrap();
        assert_eq!(version, 1);

        let deriv_paths = decode_derivation_paths(&bytes).unwrap();
        assert!(deriv_paths.is_empty());

        let (_, individual_secrets, encryption_type, nonce, cyphertext) =
            decode_v1(&bytes).unwrap();
        assert_eq!(encryption_type, 0x01);

        let (content, decrypted_1) =
            decrypt_aes_gcm_256_v1(pk1(), &individual_secrets, cyphertext.clone(), nonce).unwrap();
        assert_eq!(content, Content::None);
        assert_eq!(String::from_utf8(decrypted_1).unwrap(), "test".to_string());
        let (content, decrypted_2) =
            decrypt_aes_gcm_256_v1(pk2(), &individual_secrets, cyphertext.clone(), nonce).unwrap();
        assert_eq!(content, Content::None);
        assert_eq!(String::from_utf8(decrypted_2).unwrap(), "test".to_string());
        let decrypted_3 =
            decrypt_aes_gcm_256_v1(pk3(), &individual_secrets, cyphertext.clone(), nonce);
        assert!(decrypted_3.is_err());
    }

    #[test]
    fn test_decrypt_wrong_secret() {
        let mut engine = sha256::HashEngine::default();
        engine.input("secret".as_bytes());
        let secret = sha256::Hash::from_engine(engine);

        let mut engine = sha256::HashEngine::default();
        engine.input("wrong_secret".as_bytes());
        let wrong_secret = sha256::Hash::from_engine(engine);

        let payload = "payload".as_bytes().to_vec();
        let (nonce, ciphertext) = inner_encrypt(secret, payload).unwrap();
        // decrypting with secret success
        let _ = try_decrypt_aes_gcm_256(&ciphertext, secret.as_byte_array(), nonce).unwrap();
        // decrypting with wrong secret fails
        let fails = try_decrypt_aes_gcm_256(&ciphertext, wrong_secret.as_byte_array(), nonce);
        assert!(fails.is_none());
    }

    #[test]
    fn test_decrypt_wrong_nonce() {
        let mut engine = sha256::HashEngine::default();
        engine.input("secret".as_bytes());
        let secret = sha256::Hash::from_engine(engine);

        let payload = "payload".as_bytes().to_vec();
        let (nonce, ciphertext) = inner_encrypt(secret, payload).unwrap();
        // decrypting with correct nonce success
        let _ = try_decrypt_aes_gcm_256(&ciphertext, secret.as_byte_array(), nonce).unwrap();
        // decrypting with wrong nonce fails
        let nonce = [0xF1; 12];
        let fails = try_decrypt_aes_gcm_256(&ciphertext, secret.as_byte_array(), nonce);
        assert!(fails.is_none());
    }

    #[test]
    fn test_decrypt_corrupted_ciphertext_fails() {
        let mut engine = sha256::HashEngine::default();
        engine.input("secret".as_bytes());
        let secret = sha256::Hash::from_engine(engine);

        let payload = "payload".as_bytes().to_vec();
        let (nonce, mut ciphertext) = inner_encrypt(secret, payload).unwrap();
        // decrypting with secret success
        let _ = try_decrypt_aes_gcm_256(&ciphertext, secret.as_byte_array(), nonce).unwrap();

        // corrupting the ciphertext
        let offset = ciphertext.len() - 10;
        for i in offset..offset + 5 {
            *ciphertext.get_mut(i).unwrap() = 0;
        }

        // decryption must then fails
        let fails = try_decrypt_aes_gcm_256(&ciphertext, secret.as_byte_array(), nonce);
        assert!(fails.is_none());
    }
}
