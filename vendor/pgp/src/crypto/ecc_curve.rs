use const_oid::ObjectIdentifier;

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::unsupported_err,
};

#[derive(Clone, Debug, Eq, PartialEq)]

pub enum ECCCurve {
    Curve25519Legacy,
    Ed25519Legacy,
    P256,
    P384,
    P521,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    Secp256k1,

    Unknown(ObjectIdentifier),
}

impl ECCCurve {
    pub fn name(&self) -> &str {
        match self {
            ECCCurve::Curve25519Legacy => "Curve25519Legacy",
            ECCCurve::Ed25519Legacy => "Ed25519Legacy",
            ECCCurve::P256 => "NIST P-256",
            ECCCurve::P384 => "NIST P-384",
            ECCCurve::P521 => "NIST P-521",
            ECCCurve::BrainpoolP256r1 => "brainpoolP256r1",
            ECCCurve::BrainpoolP384r1 => "brainpoolP384r1",
            ECCCurve::BrainpoolP512r1 => "brainpoolP512r1",
            ECCCurve::Secp256k1 => "secp256k1",
            ECCCurve::Unknown(_oid) => "unknown",
        }
    }

    pub fn oid_str(&self) -> String {
        match self {
            ECCCurve::Curve25519Legacy => "1.3.6.1.4.1.3029.1.5.1".into(),
            ECCCurve::Ed25519Legacy => "1.3.6.1.4.1.11591.15.1".into(),
            ECCCurve::P256 => "1.2.840.10045.3.1.7".into(),
            ECCCurve::P384 => "1.3.132.0.34".into(),
            ECCCurve::P521 => "1.3.132.0.35".into(),
            ECCCurve::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.1.7".into(),
            ECCCurve::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.1.11".into(),
            ECCCurve::BrainpoolP512r1 => "1.3.36.3.3.2.8.1.1.13".into(),
            ECCCurve::Secp256k1 => "1.3.132.0.10".into(),
            ECCCurve::Unknown(oid) => oid.to_string(),
        }
    }

    pub fn nbits(&self) -> u16 {
        match self {
            ECCCurve::Curve25519Legacy => 255,
            ECCCurve::Ed25519Legacy => 255,
            ECCCurve::P256 => 256,
            ECCCurve::P384 => 384,
            ECCCurve::P521 => 521,
            ECCCurve::BrainpoolP256r1 => 256,
            ECCCurve::BrainpoolP384r1 => 384,
            ECCCurve::BrainpoolP512r1 => 512,
            ECCCurve::Secp256k1 => 256,
            ECCCurve::Unknown(_oid) => 0,
        }
    }

    pub const fn secret_key_length(&self) -> usize {
        match self {
            ECCCurve::Curve25519Legacy => 32,
            ECCCurve::Ed25519Legacy => 32,
            ECCCurve::P256 => 32,
            ECCCurve::P384 => 48,
            ECCCurve::P521 => 66,
            ECCCurve::BrainpoolP256r1 => 32,
            ECCCurve::BrainpoolP384r1 => 48,
            ECCCurve::BrainpoolP512r1 => 64,
            ECCCurve::Secp256k1 => 32,
            ECCCurve::Unknown(_oid) => 0,
        }
    }

    pub fn alias(&self) -> Option<&str> {
        match self {
            ECCCurve::Curve25519Legacy => Some("cv25519"),
            ECCCurve::Ed25519Legacy => Some("ed25519"),
            ECCCurve::P256 => Some("nistp256"),
            ECCCurve::P384 => Some("nistp384"),
            ECCCurve::P521 => Some("nistp521"),
            ECCCurve::BrainpoolP256r1 => None,
            ECCCurve::BrainpoolP384r1 => None,
            ECCCurve::BrainpoolP512r1 => None,
            ECCCurve::Secp256k1 => None,
            ECCCurve::Unknown(_oid) => None,
        }
    }

    pub fn pubkey_algo(&self) -> Option<PublicKeyAlgorithm> {
        match self {
            ECCCurve::Curve25519Legacy => Some(PublicKeyAlgorithm::ECDH),
            ECCCurve::Ed25519Legacy => Some(PublicKeyAlgorithm::EdDSALegacy),
            ECCCurve::P256 => None,
            ECCCurve::P384 => None,
            ECCCurve::P521 => None,
            ECCCurve::BrainpoolP256r1 => None,
            ECCCurve::BrainpoolP384r1 => None,
            ECCCurve::BrainpoolP512r1 => None,
            ECCCurve::Secp256k1 => None,
            ECCCurve::Unknown(_oid) => None,
        }
    }

    pub fn hash_algo(&self) -> crate::errors::Result<HashAlgorithm> {
        match self {
            ECCCurve::Curve25519Legacy
            | ECCCurve::Ed25519Legacy
            | ECCCurve::P256
            | ECCCurve::BrainpoolP256r1
            | ECCCurve::Secp256k1 => Ok(HashAlgorithm::Sha256),

            ECCCurve::P384 | ECCCurve::BrainpoolP384r1 => Ok(HashAlgorithm::Sha384),

            ECCCurve::P521 | ECCCurve::BrainpoolP512r1 => Ok(HashAlgorithm::Sha512),

            ECCCurve::Unknown(_oid) => {
                unsupported_err!("no default hash_algo for curve {:?}", self.to_string())
            }
        }
    }

    pub fn sym_algo(&self) -> crate::errors::Result<SymmetricKeyAlgorithm> {
        match self {
            ECCCurve::Curve25519Legacy
            | ECCCurve::Ed25519Legacy
            | ECCCurve::P256
            | ECCCurve::BrainpoolP256r1
            | ECCCurve::Secp256k1 => Ok(SymmetricKeyAlgorithm::AES128),

            ECCCurve::P384 | ECCCurve::BrainpoolP384r1 => Ok(SymmetricKeyAlgorithm::AES192),

            ECCCurve::P521 | ECCCurve::BrainpoolP512r1 => Ok(SymmetricKeyAlgorithm::AES256),

            ECCCurve::Unknown(_oid) => {
                unsupported_err!("no default sym_algo for curve {:?}", self.to_string())
            }
        }
    }

    pub fn oid(&self) -> Vec<u8> {
        let mut id: Vec<u32> = self
            .oid_str()
            .split('.')
            .map(|v| v.parse::<u32>().expect("bad oid string"))
            .collect();

        let first = id.remove(0) * 40 + id.remove(0);
        id.insert(0, first);

        id.iter()
            .flat_map(|ident| asn1_der_object_id_val_enc(*ident))
            .collect()
    }
}
pub fn ecc_curve_from_oid(oid: &[u8]) -> Option<ECCCurve> {
    if ECCCurve::Curve25519Legacy.oid().as_slice() == oid {
        return Some(ECCCurve::Curve25519Legacy);
    }
    if ECCCurve::Ed25519Legacy.oid().as_slice() == oid {
        return Some(ECCCurve::Ed25519Legacy);
    }
    if ECCCurve::P256.oid().as_slice() == oid {
        return Some(ECCCurve::P256);
    }
    if ECCCurve::P384.oid().as_slice() == oid {
        return Some(ECCCurve::P384);
    }
    if ECCCurve::P521.oid().as_slice() == oid {
        return Some(ECCCurve::P521);
    }
    if ECCCurve::BrainpoolP256r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP256r1);
    }
    if ECCCurve::BrainpoolP384r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP384r1);
    }
    if ECCCurve::BrainpoolP512r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP512r1);
    }
    if ECCCurve::Secp256k1.oid().as_slice() == oid {
        return Some(ECCCurve::Secp256k1);
    }

    if let Ok(oid) = ObjectIdentifier::from_bytes(oid) {
        Some(ECCCurve::Unknown(oid))
    } else {
        None
    }
}

fn asn1_der_object_id_val_enc(val: u32) -> Vec<u8> {
    let mut val = val;
    let mut acc = vec![(val & 0x7f) as u8];
    val >>= 7;

    while val > 0 {
        acc.insert(0, (0x80 | (val & 0x7f)) as u8);
        val >>= 7;
    }

    acc
}

impl std::fmt::Display for ECCCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}
