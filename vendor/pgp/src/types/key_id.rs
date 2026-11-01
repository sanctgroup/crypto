#[derive(Clone, Copy, Hash, Eq, PartialEq, derive_more::Debug, derive_more::Display)]
#[display("{}", hex::encode(_0))]

pub struct KeyId(#[debug("{}", hex::encode(_0))] [u8; 8]);

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 8]> for KeyId {
    fn from(value: [u8; 8]) -> Self {
        Self::new(value)
    }
}

impl KeyId {
    pub const WILDCARD: KeyId = KeyId([0u8; 8]);

    pub const fn new(id: [u8; 8]) -> Self {
        Self(id)
    }

    pub fn is_wildcard(&self) -> bool {
        self == &Self::WILDCARD
    }
}
