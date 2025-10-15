#[cfg(feature = "miniscript_12_0")]
pub use mscript_12_0 as miniscript;
#[cfg(feature = "miniscript_12_3_5")]
pub use mscript_12_3_5 as miniscript;

extern crate alloc;

use alloc::{collections::BTreeSet, str::FromStr, vec::Vec};

use miniscript::{
    bitcoin::{self, bip32::DerivationPath, secp256k1},
    Descriptor, DescriptorPublicKey, ForEachKey,
};

use crate::Error;

pub fn dpk_to_pk(key: &DescriptorPublicKey) -> bitcoin::secp256k1::PublicKey {
    match key {
        DescriptorPublicKey::Single(key) => match key.key {
            miniscript::descriptor::SinglePubKey::FullKey(pk) => pk.inner,
            miniscript::descriptor::SinglePubKey::XOnly(pk) => {
                pk.public_key(bitcoin::key::Parity::Even)
            }
        },
        DescriptorPublicKey::XPub(key) => key.xkey.public_key,
        DescriptorPublicKey::MultiXPub(key) => key.xkey.public_key,
    }
}

fn dpk_to_deriv_path(key: &DescriptorPublicKey) -> Option<DerivationPath> {
    match key {
        DescriptorPublicKey::Single(key) => key.origin.clone().map(|(_, p)| p),
        DescriptorPublicKey::XPub(key) => key.origin.clone().map(|(_, p)| p),
        DescriptorPublicKey::MultiXPub(key) => key.origin.clone().map(|(_, p)| p),
    }
}

// See
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs:
// > One example of such a point is H =
// > lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0) which is constructed
// > by taking the hash of the standard uncompressed encoding of the secp256k1 base point G as X
// > coordinate.
pub fn bip341_nums() -> bitcoin::secp256k1::PublicKey {
    bitcoin::secp256k1::PublicKey::from_str(
        "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .expect("Valid pubkey: NUMS from BIP341")
}

pub fn descr_to_dpks(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<Vec<DescriptorPublicKey>, Error> {
    let mut keys = BTreeSet::new();
    descriptor.for_each_key(|k| {
        let pk = dpk_to_pk(k);
        if pk != bip341_nums() {
            keys.insert(k.clone());
        }
        true
    });
    let keys: Vec<_> = keys.into_iter().collect();

    if keys.is_empty() {
        Err(Error::DescriptorHasNoKeys)
    } else {
        Ok(keys)
    }
}

pub fn dpks_to_derivation_keys_paths(
    dpks: &Vec<DescriptorPublicKey>,
) -> (Vec<secp256k1::PublicKey>, Vec<DerivationPath>) {
    let mut derivation_paths = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for k in dpks {
        keys.insert(dpk_to_pk(k));
        if let Some(path) = dpk_to_deriv_path(k) {
            derivation_paths.insert(path);
        }
    }
    let deriv = derivation_paths.into_iter().collect();
    let keys = keys.into_iter().collect();
    (keys, deriv)
}

#[cfg(all(test, feature = "rand"))]
pub mod tests {
    use super::*;
    use alloc::{str::FromStr, vec};

    use miniscript::{
        bitcoin::bip32::{self, ChainCode, ChildNumber, Fingerprint},
        descriptor::{
            self, DerivPaths, DescriptorMultiXKey, DescriptorXKey, SinglePub, SinglePubKey,
            Wildcard,
        },
        Descriptor, DescriptorPublicKey, ToPublicKey,
    };

    pub fn descr_1() -> Descriptor<DescriptorPublicKey> {
        let descr_str = "wsh(or_d(pk([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*),and_v(v:pkh([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*),older(52596))))#pggrcdd0";

        Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap()
    }

    pub fn dpk_1() -> DescriptorPublicKey {
        let dpk_str = "[58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*";
        DescriptorPublicKey::from_str(dpk_str).unwrap()
    }

    fn dpk_2() -> DescriptorPublicKey {
        let dpk_str = "[58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*";
        DescriptorPublicKey::from_str(dpk_str).unwrap()
    }

    fn dpk_3() -> DescriptorPublicKey {
        let dpk_str = "tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*";
        DescriptorPublicKey::from_str(dpk_str).unwrap()
    }
    pub fn pk() -> secp256k1::PublicKey {
        let raw = [
            3, 235, 210, 82, 202, 8, 119, 170, 224, 155, 157, 5, 130, 25, 104, 39, 117, 170, 60,
            188, 208, 73, 193, 47, 7, 131, 47, 44, 246, 163, 181, 23, 8,
        ];
        secp256k1::PublicKey::from_slice(&raw).unwrap()
    }

    #[test]
    fn test_dpk_to_pk() {
        let expected = pk();
        let pk = dpk_to_pk(&dpk_1());
        assert_eq!(pk, expected);
        let pk = dpk_to_pk(&dpk_2());
        assert_eq!(pk, expected);

        // Single
        let single_str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        let dpk = DescriptorPublicKey::from_str(single_str).unwrap();
        let pk = dpk_to_pk(&dpk);
        let expected = bitcoin::secp256k1::PublicKey::from_str(single_str).unwrap();
        assert_eq!(expected, pk);

        // Single Xonly
        let xonly = bitcoin::PublicKey::from_str(single_str)
            .unwrap()
            .to_x_only_pubkey();
        let dpk = DescriptorPublicKey::Single(SinglePub {
            origin: None,
            key: descriptor::SinglePubKey::XOnly(xonly),
        });
        let pk = dpk_to_pk(&dpk);
        assert_eq!(expected, pk);

        // Xpub
        let xpub = bip32::Xpub {
            network: bitcoin::NetworkKind::Test,
            depth: 1,
            parent_fingerprint: Fingerprint::from_str("00000000").unwrap(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: bitcoin::secp256k1::PublicKey::from_str(single_str).unwrap(),
            chain_code: ChainCode::from(&[1u8; 32]),
        };
        let dpk = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: xpub,
            derivation_path: DerivationPath::default(),
            wildcard: Wildcard::None,
        });
        let pk = dpk_to_pk(&dpk);
        assert_eq!(expected, pk);

        // MultiXpub
        let dpk = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: None,
            xkey: xpub,
            derivation_paths: DerivPaths::new(vec![DerivationPath::from_str("0").unwrap()])
                .unwrap(),
            wildcard: Wildcard::None,
        });
        let pk = dpk_to_pk(&dpk);
        assert_eq!(expected, pk);
    }

    #[test]
    fn test_dpk_to_deriv() {
        let deriv_1 = dpk_to_deriv_path(&dpk_1()).unwrap();
        assert_eq!(deriv_1, DerivationPath::from_str("48'/1'/0'/2'").unwrap());
        let deriv_2 = dpk_to_deriv_path(&dpk_2()).unwrap();
        assert_eq!(deriv_2, DerivationPath::from_str("48'/1'/0'/2'").unwrap());
        let deriv_3 = dpk_to_deriv_path(&dpk_3());
        assert!(deriv_3.is_none());

        let dp = DerivationPath::from_str("0/0").unwrap();
        let origin = Some((Fingerprint::from_str("aabbccdd").unwrap(), dp.clone()));

        // Single
        let single_str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        let dpk = DescriptorPublicKey::from_str(single_str).unwrap();
        let none = dpk_to_deriv_path(&dpk);
        assert!(none.is_none());
        let single_pk = SinglePubKey::FullKey(dpk_to_pk(&dpk).into());
        let dpk = DescriptorPublicKey::Single(SinglePub {
            origin: origin.clone(),
            key: single_pk,
        });
        let deriv = dpk_to_deriv_path(&dpk).unwrap();
        assert_eq!(deriv, dp);

        // Xpub
        let xpub = bip32::Xpub {
            network: bitcoin::NetworkKind::Test,
            depth: 1,
            parent_fingerprint: Fingerprint::from_str("00000000").unwrap(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            public_key: bitcoin::secp256k1::PublicKey::from_str(single_str).unwrap(),
            chain_code: ChainCode::from(&[1u8; 32]),
        };
        let dpk = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: None,
            xkey: xpub,
            derivation_path: DerivationPath::default(),
            wildcard: Wildcard::None,
        });
        let none = dpk_to_deriv_path(&dpk);
        assert!(none.is_none());
        let dpk = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: origin.clone(),
            xkey: xpub,
            derivation_path: DerivationPath::default(),
            wildcard: Wildcard::None,
        });
        let deriv = dpk_to_deriv_path(&dpk).unwrap();
        assert_eq!(deriv, dp);

        // MultiXpub
        let dpk = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: None,
            xkey: xpub,
            derivation_paths: DerivPaths::new(vec![DerivationPath::from_str("0").unwrap()])
                .unwrap(),
            wildcard: Wildcard::None,
        });
        let none = dpk_to_deriv_path(&dpk);
        assert!(none.is_none());
        let dpk = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: origin.clone(),
            xkey: xpub,
            derivation_paths: DerivPaths::new(vec![DerivationPath::from_str("0").unwrap()])
                .unwrap(),
            wildcard: Wildcard::None,
        });
        let deriv = dpk_to_deriv_path(&dpk).unwrap();
        assert_eq!(deriv, dp);
    }

    #[test]
    fn test_descript_to_dpk() {
        let dpks = descr_to_dpks(&descr_1()).unwrap();
        let expected = vec![dpk_1(), dpk_2()];
        assert_eq!(dpks, expected);
    }

    #[test]
    fn test_descriptor_to_dpk_unspendable() {
        let descr_str = "tr(tpubD6NzVbkrYhZ4XWBqjZ7DTB4eFvi8eQZ79UvNbQFsxXiaMNaBn83jpMWTXLX2Gx6JgC5n9jWvx6vnijcAUgxXmRtFd4ntasRGNsYSCvQteSr/<0;1>/*,{and_v(v:and_v(v:pk([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<2;3>/*),pk([79af2d8a/48'/1'/0'/2']tpubDEtHs6m9crfv1oeETj6EXteAtW7eoSSBVBaypEdWZt8VftbHF9R12xSZpzWGNuAofeGPL6cz48dLdCYbVioHL8ygA56yuPW76Xz5WZ3dt8o/<2;3>/*)),older(52596)),and_v(v:pk([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<0;1>/*),pk([79af2d8a/48'/1'/0'/2']tpubDEtHs6m9crfv1oeETj6EXteAtW7eoSSBVBaypEdWZt8VftbHF9R12xSZpzWGNuAofeGPL6cz48dLdCYbVioHL8ygA56yuPW76Xz5WZ3dt8o/<0;1>/*))})#vudj49fm";
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();
        // unspendable keys must have been dropped
        let keys = descr_to_dpks(&descriptor).unwrap();
        for key in keys {
            let pk = dpk_to_pk(&key);
            assert_ne!(pk, bip341_nums());
        }
        // but the descriptor contains unspendable
        let contains_unspendable = descriptor.for_any_key(|k| {
            let pk = dpk_to_pk(k);
            pk == bip341_nums()
        });
        assert!(contains_unspendable);
    }

    #[test]
    fn test_dpks_to_deriv_paths() {
        let dpks = vec![dpk_1(), dpk_2()];
        let pks = vec![pk()];
        let deriv = vec![DerivationPath::from_str("48'/1'/0'/2'").unwrap()];
        let res = dpks_to_derivation_keys_paths(&dpks);
        assert_eq!(res, (pks, deriv));
    }
}
