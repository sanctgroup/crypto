use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum PublicKeyAlgorithm {
    RSA = 1,
    RSAEncrypt = 2,
    RSASign = 3,

    ElgamalEncrypt = 16,
    DSA = 17,
    ECDH = 18,
    ECDSA = 19,

    Elgamal = 20,

    DiffieHellman = 21,
    EdDSALegacy = 22,
    X25519 = 25,
    X448 = 26,
    Ed25519 = 27,
    Ed448 = 28,

    Private100 = 100,

    Private101 = 101,

    Private102 = 102,

    Private103 = 103,

    Private104 = 104,

    Private105 = 105,

    Private106 = 106,

    Private107 = 107,

    Private108 = 108,

    Private109 = 109,

    Private110 = 110,

    #[num_enum(catch_all)]
    Unknown(u8),
}

impl PublicKeyAlgorithm {
    pub fn is_pqc(&self) -> bool {
        match self {
            _ => false,
        }
    }

    pub fn can_sign(self) -> bool {
        use PublicKeyAlgorithm::*;

        matches!(
            self,
            RSA | RSASign | Elgamal | DSA | ECDSA | EdDSALegacy | Ed25519 | Ed448
        )
    }

    pub fn can_encrypt(self) -> bool {
        use PublicKeyAlgorithm::*;

        matches!(
            self,
            RSA | RSAEncrypt | ECDH | DiffieHellman | Elgamal | ElgamalEncrypt | X25519 | X448
        )
    }
}
