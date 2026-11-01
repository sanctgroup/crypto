mod compression;
mod duration;
mod fingerprint;
mod key_id;
mod key_traits;
mod mpi;
mod packet;
mod params;
mod password;
mod pkesk;
mod revocation_key;
mod s2k;
mod signature;
mod timestamp;
mod user;

pub use self::{
    compression::CompressionAlgorithm,
    duration::{Duration, DurationError},
    fingerprint::Fingerprint,
    key_id::KeyId,
    key_traits::{DecryptionKey, EncryptionKey, Imprint, KeyDetails, SigningKey, VerifyingKey},
    mpi::Mpi,
    packet::*,
    params::*,
    password::Password,
    pkesk::PkeskBytes,
    revocation_key::{RevocationKey, RevocationKeyClass},
    s2k::{S2kParams, S2kUsage, StringToKey},
    signature::SignatureBytes,
    timestamp::{Timestamp, TimestampError},
    user::{SignedUser, SignedUserAttribute},
};

#[derive(Debug, Copy, Clone)]
pub enum EskType {
    V3_4,

    V6,
}

#[derive(derive_more::Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seipdv1ReadMode {
    CheckFirst { max_message_size: usize },
    Streaming,
}

const MAX_DEFAULT_UNSTREAMED_MSG_SIZE: usize = 1024 * 1024 * 1024;

impl Default for Seipdv1ReadMode {
    fn default() -> Self {
        Self::CheckFirst {
            max_message_size: MAX_DEFAULT_UNSTREAMED_MSG_SIZE,
        }
    }
}

#[cfg(feature = "draft-wussler-openpgp-forwarding")]
#[derive(zeroize::ZeroizeOnDrop)]
pub struct ForwardingProxyParameter([u8; 32]);

#[cfg(feature = "draft-wussler-openpgp-forwarding")]
impl From<[u8; 32]> for ForwardingProxyParameter {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[cfg(feature = "draft-wussler-openpgp-forwarding")]
impl ForwardingProxyParameter {
    pub(crate) fn into_array(self) -> [u8; 32] {
        self.0
    }
}

#[cfg(feature = "draft-wussler-openpgp-forwarding")]
impl AsRef<[u8; 32]> for ForwardingProxyParameter {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
