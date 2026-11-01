use log::debug;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::sym::SymmetricKeyAlgorithm,
    errors::{ensure, unsupported_err, Result},
    packet::SymKeyEncryptedSessionKey,
    types::{Password, SkeskVersion},
};

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum PlainSessionKey {
    V3_4 {
        sym_alg: SymmetricKeyAlgorithm,
        key: RawSessionKey,
    },
    V5 {
        key: RawSessionKey,
    },
    V6 {
        key: RawSessionKey,
    },
}

#[derive(derive_more::Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RawSessionKey(#[debug("..")] Zeroizing<Vec<u8>>);

impl RawSessionKey {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&[u8]> for RawSessionKey {
    fn from(value: &[u8]) -> Self {
        Self(Zeroizing::new(value.to_vec()))
    }
}

impl From<Vec<u8>> for RawSessionKey {
    fn from(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl From<Zeroizing<Vec<u8>>> for RawSessionKey {
    fn from(value: Zeroizing<Vec<u8>>) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for RawSessionKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl PlainSessionKey {
    pub fn sym_algorithm(&self) -> Option<SymmetricKeyAlgorithm> {
        match self {
            Self::V3_4 { sym_alg, .. } => Some(*sym_alg),
            Self::V5 { .. } | Self::V6 { .. } => None,
        }
    }
}

pub fn decrypt_session_key_with_password(
    packet: &SymKeyEncryptedSessionKey,
    msg_pw: &Password,
) -> Result<PlainSessionKey> {
    debug!("decrypt session key with password");
    if !packet.is_supported() {
        unsupported_err!("SKESK version {:?}", packet.version());
    }

    let packet_algorithm = packet.sym_algorithm().expect("supported");
    ensure!(
        packet_algorithm != SymmetricKeyAlgorithm::Plaintext,
        "SKESK packet encryption algorithm cannot be plaintext"
    );

    let s2k = packet.s2k().expect("supported");

    if packet.version() == SkeskVersion::V6 {
        ensure!(
            !s2k.known_weak_hash_algo(),
            "Weak hash algorithm in S2K not allowed for v6 {:?}",
            packet.s2k()
        )
    }

    let key = s2k.derive_key(&msg_pw.read(), packet_algorithm.key_size())?;

    if packet.encrypted_key().expect("supported").is_empty() {
        return Ok(PlainSessionKey::V3_4 {
            key,
            sym_alg: packet_algorithm,
        });
    }

    let decrypted_key = packet.decrypt(&key)?;

    Ok(decrypted_key)
}
