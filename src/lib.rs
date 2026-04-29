// #![no_std]
use crate::alloc::string::ToString;
extern crate alloc;
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::str::FromStr;

use descriptor::descr_to_dpks;

pub use ll::Content;
use miniscript::{
    bitcoin::{bip32::DerivationPath, secp256k1},
    Descriptor, DescriptorPublicKey,
};

#[cfg(all(feature = "miniscript_12_0", feature = "miniscript_12_3_5"))]
compile_error!("A single miniscript version must be selected");

#[cfg(not(any(feature = "miniscript_12_0", feature = "miniscript_12_3_5")))]
compile_error!("A miniscript version must be selected with feature flag");
#[cfg(feature = "tokio")]
pub use tokio;

#[cfg(feature = "miniscript_12_0")]
pub use mscript_12_0 as miniscript;
#[cfg(feature = "miniscript_12_3_5")]
pub use mscript_12_3_5 as miniscript;

pub mod descriptor;
pub mod ll;
#[cfg(feature = "devices")]
pub mod signing_devices;

/// Non-fatal signal raised while extracting keys from a descriptor: a key
/// expression was sorted out of the encryption-key set. The cosigner
/// holding that key will be unable to decrypt the backup with their key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// The expression is not allowed by the BIP (e.g. literal pubkey, or
    /// bare xpub with no trailing derivation and no wildcard).
    DisallowedKeyExpression(DescriptorPublicKey),
    /// The expression resolves to the BIP341 NUMS point.
    NumsKey(DescriptorPublicKey),
}

/// Output of [`EncryptedBackup::encrypt`]: the encoded backup plus any
/// warnings raised while building the encryption-key set.
#[derive(Debug, Clone)]
pub struct Encrypted {
    pub bytes: Vec<u8>,
    pub warnings: Vec<Warning>,
}

impl Encrypted {
    /// Standard RFC 4648 base64 of the encoded backup (the format
    /// produced by bitcoin-core's wallet tool). Warnings remain
    /// accessible via `self.warnings`.
    #[cfg(feature = "base64")]
    pub fn to_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&self.bytes)
    }
}

pub trait ToPayload {
    fn to_payload(&self) -> Result<Vec<u8>, Error>;
    fn content_type(&self) -> Content;
    fn derivation_paths(&self) -> Result<Vec<DerivationPath>, Error>;
    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error>;
    /// Warnings about filtered key expressions. Default empty.
    fn warnings(&self) -> Result<Vec<Warning>, Error> {
        Ok(vec![])
    }
}

impl ToPayload for Vec<u8> {
    fn to_payload(&self) -> Result<Vec<u8>, Error> {
        Ok(self.clone())
    }
    fn content_type(&self) -> Content {
        Content::Unknown
    }
    fn derivation_paths(&self) -> Result<Vec<DerivationPath>, Error> {
        Ok(vec![])
    }
    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error> {
        Ok(vec![])
    }
}

impl ToPayload for Descriptor<DescriptorPublicKey> {
    fn to_payload(&self) -> Result<Vec<u8>, Error> {
        Ok(self.to_string().as_bytes().to_vec())
    }

    fn content_type(&self) -> Content {
        Content::Bip380
    }

    fn derivation_paths(&self) -> Result<Vec<DerivationPath>, Error> {
        let dpks = descr_to_dpks(self)?;
        let (_, p) = descriptor::dpks_to_derivation_keys_paths(&dpks);
        Ok(p)
    }

    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error> {
        let dpks = descr_to_dpks(self)?;
        let (k, _) = descriptor::dpks_to_derivation_keys_paths(&dpks);
        Ok(k)
    }

    fn warnings(&self) -> Result<Vec<Warning>, Error> {
        descriptor::descr_warnings(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decrypted {
    Descriptor(Descriptor<DescriptorPublicKey>),
    Policy,
    Labels,
    WalletBackup(Vec<u8>),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum Payload {
    None,
    Encrypt {
        payload: Vec<u8>,
    },
    DecryptV1 {
        cyphertext: Vec<u8>,
        individual_secrets: Vec<[u8; 32]>,
        nonce: [u8; 12],
    },
    /// Raw bytes of a backup produced by bitcoin-encrypted-backup 0.0.2
    /// (BEB magic, AES-256-GCM). Decryption is delegated to the v0 crate;
    /// this crate never emits this variant from `encrypt()`.
    #[cfg(feature = "v0")]
    DecryptV0 {
        raw: Vec<u8>,
    },
}

impl Payload {
    pub fn is_none(&self) -> bool {
        matches!(self, Payload::None)
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedBackup {
    version: Version,
    content: Content,
    encryption: Encryption,
    derivation_paths: Vec<DerivationPath>,
    keys: Vec<secp256k1::PublicKey>,
    payload: Payload,
    warnings: Vec<Warning>,
}

impl Default for EncryptedBackup {
    fn default() -> Self {
        Self {
            version: Version::V1,
            content: Content::Unknown,
            encryption: Encryption::ChaCha20Poly1305,
            derivation_paths: vec![],
            keys: vec![],
            payload: Payload::None,
            warnings: vec![],
        }
    }
}

impl EncryptedBackup {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn get_derivation_paths(&self) -> Vec<DerivationPath> {
        self.derivation_paths.clone()
    }
    pub fn get_keys(&self) -> Vec<secp256k1::PublicKey> {
        self.keys.clone()
    }
    pub fn get_content(&self) -> Content {
        self.content.clone()
    }
    pub fn get_version(&self) -> Version {
        self.version
    }
    pub fn get_encryption(&self) -> Encryption {
        self.encryption
    }
    pub fn set_keys(mut self, keys: Vec<secp256k1::PublicKey>) -> Self {
        self.keys = keys;
        self
    }
    pub fn set_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }
    pub fn set_content_type(mut self, content_type: Content) -> Self {
        self.content = content_type;
        self
    }
    pub fn set_encryption(mut self, encryption: Encryption) -> Self {
        self.encryption = encryption;
        self
    }
    pub fn set_derivation_paths(mut self, derivation_paths: Vec<DerivationPath>) -> Self {
        self.derivation_paths = derivation_paths;
        self
    }
    pub fn set_payload<T: ToPayload>(mut self, payload: &T) -> Result<Self, Error> {
        self.payload = Payload::Encrypt {
            payload: payload.to_payload()?,
        };
        if payload.content_type().is_known() {
            self.content = payload.content_type();
        };
        self.derivation_paths
            .append(&mut payload.derivation_paths()?);
        self.keys.append(&mut payload.keys()?);
        self.warnings.append(&mut payload.warnings()?);
        Ok(self)
    }
    pub fn get_warnings(&self) -> &[Warning] {
        &self.warnings
    }
    pub fn encrypt(
        self,
        #[cfg(not(feature = "rand"))] nonce: [u8; 12],
    ) -> Result<Encrypted, Error> {
        if self.content == Content::Unknown {
            return Err(Error::UnknownContent);
        }
        if !self.encryption.is_defined() {
            return Err(Error::EncryptionUndefined);
        }
        if !self.version.is_valid() {
            return Err(Error::InvalidVersion);
        }
        let bytes = if let Payload::Encrypt { payload } = &self.payload {
            payload.clone()
        } else {
            return Err(Error::WrongPayload);
        };

        let warnings = self.warnings.clone();
        match (self.encryption, self.version) {
            (Encryption::ChaCha20Poly1305, Version::V1) => {
                let bytes = ll::encrypt_chacha20_poly1305_v1(
                    self.derivation_paths,
                    self.content.clone(),
                    self.keys,
                    &bytes,
                    #[cfg(not(feature = "rand"))]
                    nonce,
                )?;
                Ok(Encrypted { bytes, warnings })
            }
            _ => Err(Error::NotImplemented),
        }
    }
    pub fn set_encrypted_payload(
        #[cfg_attr(not(feature = "v0"), allow(unused_mut))] mut self,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        // Auto-detect: the binary BIPXXX blob always starts with the
        // 6-byte ASCII magic "BIPXXX". If the input does not start with
        // that prefix, try decoding it as standard RFC 4648 base64 (the
        // format produced by bitcoin-core's wallet tool). Base64 of any
        // BIPXXX blob starts with "Qkl..." so the check is unambiguous.
        if bytes.starts_with(ll::MAGIC.as_bytes()) {
            return self.set_encrypted_payload_binary(bytes);
        }
        #[cfg(feature = "v0")]
        if bytes.starts_with(V0_MAGIC) {
            self.payload = Payload::DecryptV0 {
                raw: bytes.to_vec(),
            };
            return Ok(self);
        }
        #[cfg(feature = "base64")]
        {
            use base64::Engine as _;
            let text = core::str::from_utf8(bytes).map_err(|_| Error::Base64)?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|_| Error::Base64)?;
            self.set_encrypted_payload_binary(&decoded)
        }
        #[cfg(not(feature = "base64"))]
        self.set_encrypted_payload_binary(bytes)
    }

    fn set_encrypted_payload_binary(mut self, bytes: &[u8]) -> Result<Self, Error> {
        #[cfg(feature = "v0")]
        if bytes.starts_with(V0_MAGIC) {
            self.payload = Payload::DecryptV0 {
                raw: bytes.to_vec(),
            };
            return Ok(self);
        }
        let version: Version = ll::decode_version(bytes).map(|v| v.into())?;
        match version {
            Version::V1 => {
                let (derivation_paths, individual_secrets, encryption_type, nonce, cyphertext) =
                    ll::decode_v1(bytes)?;
                self.derivation_paths = derivation_paths;
                self.encryption = encryption_type.into();
                self.payload = Payload::DecryptV1 {
                    cyphertext,
                    individual_secrets,
                    nonce,
                }
            }
            _ => return Err(Error::NotImplemented),
        }
        Ok(self)
    }
    pub fn extract(content: Content, bytes: Vec<u8>) -> Result<Decrypted, Error> {
        match content {
            Content::None | Content::Unknown => Ok(Decrypted::Raw(bytes)),
            Content::Bip380 => {
                let descr_str = String::from_utf8(bytes).map_err(|_| Error::Utf8)?;
                let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descr_str)
                    .map_err(|_| Error::Descriptor)?;
                Ok(Decrypted::Descriptor(descriptor))
            }
            Content::BIP(_) | Content::Proprietary(_) | Content::Bip329 | Content::Bip388 => {
                Err(Error::NotImplemented)
            }
        }
    }
    pub fn decrypt(&self) -> Result<Decrypted, Error> {
        if self.keys.is_empty() {
            return Err(Error::NoKey);
        }
        #[cfg(feature = "v0")]
        if let Payload::DecryptV0 { raw } = &self.payload {
            return self.try_v0_decrypt(raw);
        }
        match self.version {
            Version::V1 => match &self.payload {
                Payload::None | Payload::Encrypt { .. } => Err(Error::WrongPayload),
                Payload::DecryptV1 {
                    cyphertext,
                    individual_secrets,
                    nonce,
                } => {
                    for key in &self.keys {
                        if let Ok((content, bytes)) = ll::decrypt_chacha20_poly1305_v1(
                            *key,
                            &individual_secrets.clone(),
                            cyphertext.clone(),
                            *nonce,
                        ) {
                            return Self::extract(content, bytes);
                        }
                    }
                    Err(Error::WrongKey)
                }
                #[cfg(feature = "v0")]
                Payload::DecryptV0 { .. } => unreachable!("handled above"),
            },
            Version::V0 => Err(Error::NotImplemented),
            Version::Unknown => Err(Error::UnknownVersion),
        }
    }

    /// Decrypt a backup produced by bitcoin-encrypted-backup 0.0.2.
    /// Both crates pin the same miniscript version with identical
    /// features, so `Descriptor<DescriptorPublicKey>` is the same type
    /// across the boundary and no re-parsing is needed.
    #[cfg(feature = "v0")]
    fn try_v0_decrypt(&self, raw: &[u8]) -> Result<Decrypted, Error> {
        use bitcoin_encrypted_backup_v0 as v0;
        let res = v0::EncryptedBackup::new()
            .set_encrypted_payload(raw)
            .map_err(|_| Error::WrongPayload)?
            .set_keys(self.keys.clone())
            .decrypt()
            .map_err(|e| match e {
                v0::Error::NoKey => Error::NoKey,
                v0::Error::WrongKey => Error::WrongKey,
                _ => Error::WrongPayload,
            })?;
        Ok(match res {
            v0::Decrypted::Descriptor(d) => Decrypted::Descriptor(d),
            v0::Decrypted::Policy => Decrypted::Policy,
            v0::Decrypted::Labels => Decrypted::Labels,
            v0::Decrypted::WalletBackup(b) => Decrypted::WalletBackup(b),
            v0::Decrypted::Raw(b) => Decrypted::Raw(b),
        })
    }
}

/// Magic of bitcoin-encrypted-backup 0.0.2 (the published crates.io
/// release). Hard-coded because the v0 crate keeps it as a private const.
#[cfg(feature = "v0")]
const V0_MAGIC: &[u8] = b"BEB";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    Undefined,
    ChaCha20Poly1305,
    Unknown,
}

impl From<u8> for Encryption {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Undefined,
            1 => Self::ChaCha20Poly1305,
            _ => Self::Unknown,
        }
    }
}

impl From<Encryption> for u8 {
    fn from(value: Encryption) -> Self {
        match value {
            Encryption::Undefined => 0x00,
            Encryption::ChaCha20Poly1305 => 0x01,
            Encryption::Unknown => 0xFF,
        }
    }
}

impl Encryption {
    pub fn is_defined(&self) -> bool {
        match self {
            Encryption::Undefined | Encryption::Unknown => false,
            Encryption::ChaCha20Poly1305 => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V0,
    V1,
    Unknown,
}

impl From<Version> for u8 {
    fn from(value: Version) -> Self {
        match value {
            Version::V0 => 0,
            Version::V1 => 1,
            Version::Unknown => 0xFF,
        }
    }
}

impl From<u8> for Version {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::V0,
            1 => Self::V1,
            _ => Self::Unknown,
        }
    }
}

impl Version {
    fn max() -> Self {
        Version::V1
    }
    pub fn is_valid(&self) -> bool {
        match self {
            Version::Unknown => false,
            Version::V0 | Version::V1 => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Ll(ll::Error),
    Utf8,
    Descriptor,
    NotImplemented,
    UnknownContent,
    EncryptionUndefined,
    InvalidVersion,
    WrongPayload,
    UnknownVersion,
    NoKey,
    WrongKey,
    DescriptorHasNoKeys,
    Base64,
    InvalidKeyExpression,
    String(Box<String>),
}

impl From<ll::Error> for Error {
    fn from(value: ll::Error) -> Self {
        Error::Ll(value)
    }
}

#[cfg(all(test, feature = "rand"))]
mod tests {
    use miniscript::bitcoin;

    use crate::descriptor::dpk_to_pk;

    use super::*;

    #[test]
    fn test_simple_encrypted_descriptor() {
        let descriptor = descriptor::tests::descr_1();
        let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
        let keys = backp.get_keys();
        let bytes = backp.encrypt().unwrap().bytes;
        let restored = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(keys)
            .decrypt()
            .unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));
    }

    #[test]
    fn test_encrypt_bytes() {
        let payload = vec![0x00u8, 0x00, 0x00];
        let mut backp = EncryptedBackup::new().set_payload(&payload).unwrap();
        assert!(!backp.payload.is_none());

        assert!(backp.get_keys().is_empty());
        let pk1 = dpk_to_pk(&descriptor::tests::dpk_1()).unwrap();
        backp = backp.set_keys(vec![pk1]);
        let pks = backp.get_keys();
        assert_eq!(pks.len(), 1);
        assert_eq!(*pks.first().unwrap(), pk1);

        assert!(backp.get_derivation_paths().is_empty());
        let deriv = DerivationPath::from_str("0/0").unwrap();
        backp = backp.set_derivation_paths(vec![deriv.clone()]);
        assert_eq!(backp.get_derivation_paths(), vec![deriv]);

        assert_eq!(backp.get_content(), Content::Unknown);
        let fail = backp.clone().encrypt().unwrap_err();
        assert_eq!(fail, Error::UnknownContent);
        backp = backp.set_content_type(Content::Bip380);
        assert_eq!(backp.get_content(), Content::Bip380);

        assert_eq!(backp.get_encryption(), Encryption::ChaCha20Poly1305);
        backp = backp.set_encryption(Encryption::Undefined);
        assert_eq!(backp.get_encryption(), Encryption::Undefined);
        let fail = backp.clone().encrypt().unwrap_err();
        assert_eq!(fail, Error::EncryptionUndefined);
        backp = backp.set_encryption(Encryption::ChaCha20Poly1305);
        assert_eq!(backp.get_encryption(), Encryption::ChaCha20Poly1305);

        backp = backp.set_version(Version::Unknown);
        let fail = backp.clone().encrypt().unwrap_err();
        assert_eq!(fail, Error::InvalidVersion);
        backp = backp.set_version(Version::V0);
        assert_eq!(backp.get_version(), Version::V0);
        backp = backp.set_version(Version::V1);
        assert_eq!(backp.get_version(), Version::V1);

        let bytes = backp.encrypt().unwrap().bytes;

        let fail = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .decrypt()
            .unwrap_err();
        assert_eq!(fail, Error::NoKey);

        let w_key = bitcoin::secp256k1::PublicKey::from_slice(&[
            4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85,
            220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124,
            149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195,
            155, 51, 247, 123, 113, 60, 228, 188,
        ])
        .unwrap();
        let fail = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(vec![w_key])
            .decrypt()
            .unwrap_err();
        assert_eq!(fail, Error::WrongKey);

        // Plaintext `[0x00, 0x00, 0x00]` is not a valid descriptor string, so
        // extracting BIP380 content surfaces Error::Descriptor; proving the
        // round-trip decrypt succeeded before extract failed.
        let fail = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(vec![pk1])
            .decrypt()
            .unwrap_err();
        assert_eq!(fail, Error::Descriptor);
    }

    pub fn dummy_encrypted_payload() -> Vec<u8> {
        let key = dpk_to_pk(&descriptor::tests::dpk_1()).unwrap();
        EncryptedBackup::new()
            .set_payload(&vec![0x00])
            .unwrap()
            .set_keys(vec![key])
            .set_content_type(Content::Bip380)
            .encrypt()
            .unwrap()
            .bytes
    }

    #[test]
    fn test_encrypt_wrong_payload() {
        // No payload
        let fail = EncryptedBackup::new()
            .set_content_type(Content::Bip380)
            .encrypt()
            .unwrap_err();
        assert_eq!(fail, Error::WrongPayload);

        let dummy_payload = dummy_encrypted_payload();

        // wrong payload
        let fail = EncryptedBackup::new()
            .set_encrypted_payload(&dummy_payload)
            .unwrap()
            .set_content_type(Content::Bip380)
            .encrypt()
            .unwrap_err();
        assert_eq!(fail, Error::WrongPayload);
    }

    #[test]
    fn test_decrypt_wrong_payload() {
        let key = dpk_to_pk(&descriptor::tests::dpk_1()).unwrap();
        // No payload
        let fail = EncryptedBackup::new()
            .set_keys(vec![key])
            .decrypt()
            .unwrap_err();
        assert_eq!(fail, Error::WrongPayload);

        // wrong payload
        let fail = EncryptedBackup::new()
            .set_keys(vec![key])
            .set_payload(&vec![0x00])
            .unwrap()
            .decrypt()
            .unwrap_err();
        assert_eq!(fail, Error::WrongPayload);

        let dummy = dummy_encrypted_payload();

        // unknown version
        let fail = EncryptedBackup::new()
            .set_keys(vec![key])
            .set_encrypted_payload(&dummy)
            .unwrap()
            .set_version(Version::Unknown)
            .decrypt()
            .unwrap_err();
        assert_eq!(fail, Error::UnknownVersion);
    }

    #[test]
    fn test_multi_key_decrypt_with_each_key() {
        // Three distinct keys. Encrypt once, then confirm each of the three
        // keys can independently decrypt the payload via the high-level
        // `EncryptedBackup` API. Also confirm an unrelated key fails.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk_from = |tag: u8| {
            let mut sk = [0u8; 32];
            sk[31] = tag;
            bitcoin::secp256k1::PublicKey::from_secret_key(
                &secp,
                &bitcoin::secp256k1::SecretKey::from_slice(&sk).unwrap(),
            )
        };
        let pk1 = pk_from(1);
        let pk2 = pk_from(2);
        let pk3 = pk_from(3);
        let unrelated = pk_from(99);

        let payload = b"secret-backup-plaintext".to_vec();
        let bytes = EncryptedBackup::new()
            .set_payload(&payload)
            .unwrap()
            .set_keys(vec![pk1, pk2, pk3])
            .set_content_type(Content::Bip380)
            .encrypt()
            .unwrap()
            .bytes;

        for key in [pk1, pk2, pk3] {
            // Plaintext isn't a real descriptor, so Bip380 extract fails
            // with Error::Descriptor; that failure proves the chacha
            // decrypt step succeeded first (same signal used by
            // test_encrypt_bytes). The WrongKey case below is the
            // negative control.
            let err = EncryptedBackup::new()
                .set_encrypted_payload(&bytes)
                .unwrap()
                .set_keys(vec![key])
                .decrypt()
                .unwrap_err();
            assert_eq!(err, Error::Descriptor, "key {:?} failed decrypt", key);
        }

        let fail = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(vec![unrelated])
            .decrypt()
            .unwrap_err();
        assert_eq!(fail, Error::WrongKey);
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_base64_roundtrip() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let mut sk = [0u8; 32];
        sk[31] = 7;
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&sk).unwrap(),
        );

        let b64 = EncryptedBackup::new()
            .set_payload(&vec![0x00u8, 0x01, 0x02])
            .unwrap()
            .set_keys(vec![pk])
            .set_content_type(Content::Bip380)
            .encrypt()
            .unwrap()
            .to_base64();

        // Decrypt via auto-detected base64 input (bytes of UTF-8 string).
        let err = EncryptedBackup::new()
            .set_encrypted_payload(b64.as_bytes())
            .unwrap()
            .set_keys(vec![pk])
            .decrypt()
            .unwrap_err();
        // Plaintext isn't a valid descriptor; extract failing proves
        // the chacha decrypt step succeeded first.
        assert_eq!(err, Error::Descriptor);

        // Tolerate trailing newline (stdin-style input).
        let mut with_newline = b64.clone();
        with_newline.push('\n');
        let err = EncryptedBackup::new()
            .set_encrypted_payload(with_newline.as_bytes())
            .unwrap()
            .set_keys(vec![pk])
            .decrypt()
            .unwrap_err();
        assert_eq!(err, Error::Descriptor);
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_binary_still_works_with_base64_feature() {
        // Confirm the auto-detect logic does not regress the binary path.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let mut sk = [0u8; 32];
        sk[31] = 8;
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&sk).unwrap(),
        );
        let bytes = EncryptedBackup::new()
            .set_payload(&vec![0x00u8])
            .unwrap()
            .set_keys(vec![pk])
            .set_content_type(Content::Bip380)
            .encrypt()
            .unwrap()
            .bytes;
        let err = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(vec![pk])
            .decrypt()
            .unwrap_err();
        assert_eq!(err, Error::Descriptor);
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_malformed_input_error() {
        // Input starts neither with the magic nor decodes as valid base64.
        let garbage = b"!!!!not-valid-base64-or-magic!!!!";
        let err = EncryptedBackup::new()
            .set_encrypted_payload(garbage)
            .unwrap_err();
        assert_eq!(err, Error::Base64);
    }

    // The following tests address review feedback on the BIP that suggested
    // single-signature policies would yield c_i = 0x0...0 (i.e. a backup that
    // leaks the encryption secret in plaintext). They demonstrate the opposite:
    // because the decryption secret `s` and the per-key term `s_i` are derived
    // with *different* tagged hashes (`BIPXXX_DECRYPTION_SECRET` vs
    // `BIPXXX_INDIVIDUAL_SECRET`), `s != s_i` and so `c_1 = s ^ s_1 != 0` even
    // when n = 1.

    #[test]
    fn test_single_sig_individual_secret_is_non_zero() {
        use miniscript::bitcoin::hashes::Hash;
        // Direct math check: with a single key, s and s_1 use different tags,
        // so their XOR cannot be all-zero in any practical sense.
        let xonly = dpk_to_pk(&descriptor::tests::dpk_1())
            .unwrap()
            .x_only_public_key()
            .0
            .serialize();

        let s = ll::decryption_secret(&[xonly]);
        let s1 = ll::tagged_hash("BIPXXX_INDIVIDUAL_SECRET".as_bytes(), &xonly);
        let c1 = ll::individual_secret(&s, &xonly);

        assert_ne!(
            s.to_byte_array(),
            s1.to_byte_array(),
            "decryption secret must differ from individual term for single-sig"
        );
        assert_ne!(
            c1, [0u8; 32],
            "c_1 = s XOR s_1 must not be all-zero for single-sig (would leak the secret)"
        );
    }

    #[test]
    fn test_single_sig_wpkh_roundtrip() {
        // End-to-end round trip with a single-key wpkh() descriptor; the
        // canonical single-sig policy. Confirms that single-sig is fully
        // supported by the scheme: encrypt yields a valid blob and the same
        // single key decrypts it back to the original descriptor.
        let descr_str = "wpkh([58b7f8dc/84'/1'/0']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
        let keys = backp.get_keys();
        assert_eq!(keys.len(), 1, "wpkh is single-sig");

        let bytes = backp.encrypt().unwrap().bytes;
        let restored = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(keys)
            .decrypt()
            .unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));
    }

    #[test]
    fn test_single_sig_tr_roundtrip() {
        // Same end-to-end check for a single-key tr() (taproot) descriptor.
        let descr_str = "tr([58b7f8dc/86'/1'/0']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
        let keys = backp.get_keys();
        assert_eq!(keys.len(), 1, "tr() with no script tree is single-sig");

        let bytes = backp.encrypt().unwrap().bytes;
        let restored = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(keys)
            .decrypt()
            .unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));
    }

    #[test]
    fn test_single_sig_backup_blob_does_not_contain_zero_secret() {
        // Sanity check on the wire format: the 32-byte INDIVIDUAL_SECRET
        // embedded in a single-sig backup must not be all-zero. If it were,
        // anyone parsing the blob would recover the encryption secret
        // unconditionally.
        let descr_str = "wpkh([58b7f8dc/84'/1'/0']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let bytes = EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .encrypt()
            .unwrap()
            .bytes;

        let (_paths, secrets, _enc, _nonce, _ct) = ll::decode_v1(&bytes).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_ne!(
            secrets[0], [0u8; 32],
            "single-sig blob must not store a zeroed individual secret"
        );
    }

    // The next group of tests pins down the "Descriptor key requirements" rule
    // from the BIP: each xpub key expression must have a non-empty trailing
    // derivation OR a wildcard, and `Single` literal pubkeys are never valid.
    // The Rust impl enforces this in `descriptor::dpk_to_pk` and filters
    // invalid expressions in `descr_to_dpks` (each filtered expression
    // surfaces as a Warning), returning `Error::DescriptorHasNoKeys` only
    // when nothing valid remains.

    #[test]
    fn test_reject_bare_xpub_descriptor() {
        // wpkh(<bare xpub>); no derivation, no wildcard. The encryption seed
        // would equal the on-chain pubkey, so this expression is invalid and
        // there is no other key to fall back to.
        let descr_str = "wpkh(tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let err = EncryptedBackup::new().set_payload(&descriptor).unwrap_err();
        assert_eq!(err, Error::DescriptorHasNoKeys);
    }

    #[test]
    fn test_reject_single_literal_only_descriptor() {
        // pk(<33-byte hex>); literal Single pubkey, used on-chain verbatim.
        let descr_str = "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let err = EncryptedBackup::new().set_payload(&descriptor).unwrap_err();
        assert_eq!(err, Error::DescriptorHasNoKeys);
    }

    #[test]
    fn test_accept_xpub_fixed_deriv_no_wildcard() {
        // wpkh(xpub.../0/5); non-empty trailing derivation, no wildcard. The
        // on-chain key is xpub/0/5, distinct from the xpub root used as the
        // encryption seed, so this expression is valid.
        let descr_str = "wpkh([58b7f8dc/84'/1'/0']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/0/5)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
        let keys = backp.get_keys();
        assert_eq!(keys.len(), 1);

        let bytes = backp.encrypt().unwrap().bytes;
        let restored = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(keys)
            .decrypt()
            .unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));
    }

    #[test]
    fn test_accept_xpub_wildcard_no_extra_deriv() {
        // wpkh(xpub.../*); empty trailing derivation but a wildcard. The
        // wildcard forces a child derivation, so the on-chain key differs
        // from the xpub root.
        let descr_str = "wpkh([58b7f8dc/84'/1'/0']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/*)";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
        let keys = backp.get_keys();
        assert_eq!(keys.len(), 1);

        let bytes = backp.encrypt().unwrap().bytes;
        let restored = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(keys)
            .decrypt()
            .unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));
    }

    #[test]
    fn test_filter_partial_invalid_multikey() {
        // Mixed descriptor: one valid xpub (with /<0;1>/*) and one bare xpub.
        // The bare xpub is filtered (surfacing as a Warning); encryption
        // proceeds with the single remaining valid key. The cosigner holding
        // the filtered key cannot decrypt; only the valid key works.
        let valid_xpub = "[58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*";
        let bare_xpub = "tpubDC5FSnBiZDMmkoat4aZFfbJdEthnPqJ1jXZcKWJNKC4yJanLA55dRW5qKJRRvAo1SwaXeUx2ayUQyVJ6eCbABbBB8Wn3T7dAuVJRnZgntVC";
        let descr_str = format!("wsh(or_d(pk({}),pk({})))", valid_xpub, bare_xpub);
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descr_str).unwrap();

        let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
        let keys = backp.get_keys();
        assert_eq!(
            keys.len(),
            1,
            "bare xpub must be filtered, leaving only the valid one"
        );

        let bytes = backp.encrypt().unwrap().bytes;

        // The valid key decrypts.
        let restored = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(keys)
            .decrypt()
            .unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));

        // The filtered (bare) key does NOT decrypt; its pubkey was excluded
        // from the encryption-key set.
        let bare_pk = miniscript::bitcoin::bip32::Xpub::from_str(bare_xpub)
            .unwrap()
            .public_key;
        let err = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(vec![bare_pk])
            .decrypt()
            .unwrap_err();
        assert_eq!(err, Error::WrongKey);
    }

    #[test]
    fn test_warning_disallowed_key_expression() {
        // Multikey descriptor with one bare xpub: the bare expression must
        // surface as Warning::DisallowedKeyExpression in the Encrypted output.
        let valid_xpub = "[58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*";
        let bare_xpub = "tpubDC5FSnBiZDMmkoat4aZFfbJdEthnPqJ1jXZcKWJNKC4yJanLA55dRW5qKJRRvAo1SwaXeUx2ayUQyVJ6eCbABbBB8Wn3T7dAuVJRnZgntVC";
        let descr_str = format!("wsh(or_d(pk({valid_xpub}),pk({bare_xpub})))");
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&descr_str).unwrap();

        let encrypted = EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .encrypt()
            .unwrap();

        assert_eq!(encrypted.warnings.len(), 1, "exactly one excluded key");
        match &encrypted.warnings[0] {
            Warning::DisallowedKeyExpression(k) => {
                assert!(
                    k.to_string().contains(bare_xpub),
                    "warning carries the bare xpub"
                );
            }
            other => panic!("expected DisallowedKeyExpression, got {other:?}"),
        }
    }

    #[test]
    fn test_warning_nums_key() {
        // tr() with NUMS as the internal key: NUMS is filtered out, so the
        // descriptor's other key still encrypts and the NUMS exclusion
        // surfaces as Warning::NumsKey.
        let descr_str = "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,pk([58b7f8dc/86'/1'/0']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*))";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();

        let encrypted = EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .encrypt()
            .unwrap();

        assert!(
            encrypted
                .warnings
                .iter()
                .any(|w| matches!(w, Warning::NumsKey(_))),
            "NUMS exclusion must surface as Warning::NumsKey, got {:?}",
            encrypted.warnings
        );
    }

    #[test]
    fn test_no_warnings_on_clean_descriptor() {
        // descr_1 is a well-formed multipath multisig with no NUMS and no
        // disallowed expressions: warnings must be empty.
        let descriptor = descriptor::tests::descr_1();
        let encrypted = EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .encrypt()
            .unwrap();
        assert!(
            encrypted.warnings.is_empty(),
            "no warnings expected, got {:?}",
            encrypted.warnings
        );
    }

    #[test]
    fn test_encryption_to_u8() {
        let mut u: u8 = Encryption::ChaCha20Poly1305.into();
        assert_eq!(0x01, u);
        u = Encryption::Undefined.into();
        assert_eq!(0x00, u);
        u = Encryption::Unknown.into();
        assert_eq!(0xFF, u);
    }

    #[test]
    fn test_u8_to_encryption() {
        let mut e: Encryption = 0x00u8.into();
        assert_eq!(e, Encryption::Undefined);
        e = 0x01u8.into();
        assert_eq!(e, Encryption::ChaCha20Poly1305);

        for i in 0x02..0xFFu8 {
            e = i.into();
            assert_eq!(e, Encryption::Unknown);
        }
    }

    #[test]
    fn test_version_to_u8() {
        let mut u: u8 = Version::V0.into();
        assert_eq!(0x00, u);
        u = Version::V0.into();
        assert_eq!(0x00, u);
        u = Version::Unknown.into();
        assert_eq!(0xFF, u);
    }

    #[test]
    fn test_u8_to_version() {
        let mut v: Version = 0x00u8.into();
        assert_eq!(v, Version::V0);
        v = 0x01u8.into();
        assert_eq!(v, Version::V1);

        for i in 0x02..0xFFu8 {
            v = i.into();
            assert_eq!(v, Version::Unknown);
        }
    }
}

#[cfg(all(test, feature = "rand", feature = "v0"))]
mod v0_tests {
    use super::*;
    use crate::descriptor::dpk_to_pk;
    use bitcoin_encrypted_backup_v0 as v0;
    use miniscript::bitcoin;

    // The v0 dep is built with default-features = false, so its
    // `encrypt(nonce)` signature requires a fixed nonce.
    const NONCE: [u8; 12] = [42u8; 12];

    fn descriptor_and_key() -> (Descriptor<DescriptorPublicKey>, secp256k1::PublicKey) {
        let d = descriptor::tests::descr_1();
        let pk = dpk_to_pk(&descriptor::tests::dpk_1()).unwrap();
        (d, pk)
    }

    #[test]
    fn test_v0_roundtrip_descriptor() {
        // Encrypt with the published 0.0.2 crate, decrypt via the current
        // crate's transparent fallback. The two crates share the same
        // miniscript dep, so the Descriptor type round-trips without
        // re-parsing.
        let (descriptor, _) = descriptor_and_key();

        let bytes = v0::EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .encrypt(NONCE)
            .unwrap();

        // v0 magic check pins the assumption that BEB is the prefix.
        assert!(bytes.starts_with(V0_MAGIC), "v0 blob should start with BEB");

        let backp = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap();
        let keys = v0::EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .get_keys();
        let restored = backp.set_keys(keys).decrypt().unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));
    }

    #[test]
    fn test_v0_wrong_key_surfaces_wrong_key() {
        let (descriptor, _) = descriptor_and_key();
        let bytes = v0::EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .encrypt(NONCE)
            .unwrap();

        // Unrelated valid pubkey.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let mut sk = [0u8; 32];
        sk[31] = 99;
        let unrelated = bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&sk).unwrap(),
        );

        let err = EncryptedBackup::new()
            .set_encrypted_payload(&bytes)
            .unwrap()
            .set_keys(vec![unrelated])
            .decrypt()
            .unwrap_err();
        assert_eq!(err, Error::WrongKey);
    }

    #[test]
    fn test_garbage_returns_error_not_v0_panic() {
        // Bytes that match neither magic must return the existing parse
        // error path, not get silently routed to v0.
        let garbage = b"not-a-backup-of-any-version";
        let err = EncryptedBackup::new()
            .set_encrypted_payload(garbage)
            .unwrap_err();
        // Either Base64 (auto-detect failed to decode) or Ll (decode_v1
        // failure if base64 happened to decode); both are acceptable
        // failures - the point is we don't panic and don't silently
        // route to v0.
        assert!(matches!(err, Error::Base64 | Error::Ll(_)));
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_v0_base64_input() {
        // base64-wrapped v0 blob: auto-detect must base64-decode first,
        // then the inner bytes route to v0 via magic.
        use base64::Engine as _;
        let (descriptor, _) = descriptor_and_key();
        let bytes = v0::EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .encrypt(NONCE)
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let keys = v0::EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .get_keys();
        let restored = EncryptedBackup::new()
            .set_encrypted_payload(b64.as_bytes())
            .unwrap()
            .set_keys(keys)
            .decrypt()
            .unwrap();
        assert_eq!(restored, Decrypted::Descriptor(descriptor));
    }

    #[test]
    fn test_encrypt_never_emits_v0() {
        // Pin "decrypt-only": the current crate must always produce
        // BIPXXX blobs, never BEB. A future refactor cannot accidentally
        // re-introduce v0-format output.
        let descriptor = descriptor::tests::descr_1();
        let bytes = EncryptedBackup::new()
            .set_payload(&descriptor)
            .unwrap()
            .encrypt()
            .unwrap()
            .bytes;
        assert!(
            bytes.starts_with(ll::MAGIC.as_bytes()),
            "current encrypt must emit BIPXXX magic"
        );
        assert!(
            !bytes.starts_with(V0_MAGIC),
            "current encrypt must not emit BEB magic"
        );
    }
}
