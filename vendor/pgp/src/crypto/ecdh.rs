use bytes::BytesMut;
use log::debug;
use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::hash::HashAlgorithm;
use crate::{
    crypto::{
        aes_kw, ecc_curve::ECCCurve, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm,
        Decryptor,
    },
    errors::{bail, ensure, ensure_eq, unsupported_err, Error, Result},
    ser::Serialize,
    types::{ecdh::EcdhKdfType, pad_key, EcdhPublicParams, Mpi, PkeskBytes},
};

const ANON_SENDER: [u8; 20] = [
    0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20,
];

#[derive(Clone, ZeroizeOnDrop, derive_more::Debug)]
pub struct Curve25519Legacy(#[debug("..")] StaticSecret);

impl From<StaticSecret> for Curve25519Legacy {
    fn from(value: StaticSecret) -> Self {
        Self(value)
    }
}

impl PartialEq for Curve25519Legacy {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().eq(other.0.as_bytes())
    }
}

impl Eq for Curve25519Legacy {}

impl Curve25519Legacy {
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let mut secret_key_bytes =
            Zeroizing::new([0u8; ECCCurve::Curve25519Legacy.secret_key_length()]);
        rng.fill_bytes(&mut *secret_key_bytes);

        let q_raw = curve25519_dalek::scalar::clamp_integer(*secret_key_bytes);
        let secret = StaticSecret::from(q_raw);

        Self(secret)
    }

    pub fn try_from_bytes_rev(bytes: &[u8]) -> Result<Self> {
        let rev: Vec<u8> = bytes.iter().rev().copied().collect();
        let secret_raw = pad_key::<32>(&rev)?;
        let secret = x25519_dalek::StaticSecret::from(secret_raw);
        Ok(Self(secret))
    }

    pub fn to_bytes_rev(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (byte, o) in self.0.as_bytes().iter().rev().zip(out.iter_mut()) {
            *o = *byte;
        }
        out
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]

pub enum SecretKey {
    Curve25519Legacy(Curve25519Legacy),

    Unsupported {
        #[zeroize(skip)]
        curve: ECCCurve,

        #[debug("{}", hex::encode(mpi_data))]
        mpi_data: BytesMut,
    },
}

impl TryFrom<&SecretKey> for EcdhPublicParams {
    type Error = Error;

    fn try_from(value: &SecretKey) -> Result<Self, Self::Error> {
        let curve = value.curve();
        let hash = curve.hash_algo()?;
        let alg_sym = curve.sym_algo()?;

        match value {
            SecretKey::Curve25519Legacy(key) => Ok(Self::Curve25519Legacy {
                p: PublicKey::from(&key.0),
                hash,
                alg_sym,
                ecdh_kdf_type: EcdhKdfType::Native,
            }),

            SecretKey::Unsupported { curve, .. } => {
                bail!(
                    "Can't transform ecdh::SecretKey ({:?}) into EcdhPublicParams",
                    curve
                )
            }
        }
    }
}

impl SecretKey {
    pub fn generate<R: Rng + CryptoRng>(rng: R, curve: &ECCCurve) -> Result<Self> {
        match curve {
            ECCCurve::Curve25519Legacy => {
                let key = Curve25519Legacy::generate(rng);
                Ok(Self::Curve25519Legacy(key))
            }
            ECCCurve::P256 => return Err(crate::errors::Error::DisabledAlgorithm),
            ECCCurve::P384 => return Err(crate::errors::Error::DisabledAlgorithm),
            ECCCurve::P521 => return Err(crate::errors::Error::DisabledAlgorithm),
            _ => unsupported_err!("curve {:?} for ECDH", curve),
        }
    }

    pub(crate) fn try_from_mpi(pub_params: &EcdhPublicParams, d: Mpi) -> Result<Self> {
        match pub_params {
            EcdhPublicParams::Curve25519Legacy { .. } => {
                let key = Curve25519Legacy::try_from_bytes_rev(d.as_ref())?;
                Ok(SecretKey::Curve25519Legacy(key))
            }

            EcdhPublicParams::Brainpool256 { .. }
            | EcdhPublicParams::Brainpool384 { .. }
            | EcdhPublicParams::Brainpool512 { .. }
            | EcdhPublicParams::Unsupported { .. } => {
                let curve = pub_params.curve();
                let mpi_data = BytesMut::from(d.as_ref());
                Ok(SecretKey::Unsupported { curve, mpi_data })
            }
        }
    }

    fn to_mpi(&self) -> Mpi {
        match self {
            Self::Curve25519Legacy(key) => {
                let bytes = key.to_bytes_rev();

                Mpi::from_raw(bytes.to_vec().into())
            }

            Self::Unsupported { mpi_data, .. } => Mpi::from_raw(mpi_data.clone().into()),
        }
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Curve25519Legacy { .. } => ECCCurve::Curve25519Legacy,

            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Curve25519Legacy(key) => key.as_bytes().to_vec(),

            Self::Unsupported { mpi_data, .. } => mpi_data.to_vec(),
        }
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let x = self.to_mpi();
        x.to_writer(writer)
    }

    fn write_len(&self) -> usize {
        let x = self.to_mpi();
        x.write_len()
    }
}

pub struct EncryptionFields<'a> {
    pub public_point: &'a Mpi,

    pub encrypted_session_key: &'a [u8],

    pub fingerprint: &'a [u8],

    pub curve: ECCCurve,
    pub hash: HashAlgorithm,
    pub alg_sym: SymmetricKeyAlgorithm,
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Zeroizing<Vec<u8>>> {
        debug!("ECDH decrypt");

        let encrypted_key_len: usize = data.encrypted_session_key.len();
        let curve = data.curve;
        let alg_sym = data.alg_sym;
        let hash = data.hash;

        let shared_secret = match self {
            SecretKey::Curve25519Legacy(key) => {
                ensure_eq!(data.public_point.len(), 33, "invalid public point");

                let their_public = {
                    let ephemeral_public_key = &data.public_point.as_ref()[1..];

                    let mut ephemeral_public_key_arr = [0u8; 32];
                    ephemeral_public_key_arr[..].copy_from_slice(ephemeral_public_key);

                    x25519_dalek::PublicKey::from(ephemeral_public_key_arr)
                };

                let shared_secret = key.0.diffie_hellman(&their_public);
                if !shared_secret.was_contributory() {
                    bail!("All-zero x25519 shared secret");
                }

                shared_secret.to_bytes().to_vec()
            }

            SecretKey::Unsupported { curve, .. } => {
                bail!("unsupported ECDH curve {:?}", curve);
            }
        };

        let res = derive_session_key(
            &shared_secret,
            data.encrypted_session_key,
            encrypted_key_len,
            curve.clone(),
            hash,
            alg_sym,
            data.fingerprint,
        );

        if res.is_ok() {
            return res;
        }

        #[cfg(feature = "malformed-artifact-compat")]
        {
            log::debug!("Attempting to decrypt erroneous ECDH encryption");

            let mut strip_leading = shared_secret.as_slice();
            while strip_leading.starts_with(&[0]) {
                strip_leading = &strip_leading[1..];
            }

            if let Ok(sk) = derive_session_key(
                strip_leading,
                data.encrypted_session_key,
                encrypted_key_len,
                curve.clone(),
                hash,
                alg_sym,
                data.fingerprint,
            ) {
                log::info!("Decrypted erroneous ECDH session key by go crypto");

                return Ok(sk);
            }

            let mut strip_trailing = shared_secret.as_slice();
            while strip_trailing.ends_with(&[0]) {
                strip_trailing = &strip_trailing[..strip_trailing.len() - 1];
            }

            if let Ok(sk) = derive_session_key(
                strip_trailing,
                data.encrypted_session_key,
                encrypted_key_len,
                curve,
                hash,
                alg_sym,
                data.fingerprint,
            ) {
                log::info!("Decrypted erroneous ECDH session key by OpenPGP.js");

                return Ok(sk);
            }
        }

        res
    }
}

pub fn derive_session_key(
    shared_secret: &[u8],
    encrypted_session_key: &[u8],
    encrypted_key_len: usize,
    curve: ECCCurve,
    hash: HashAlgorithm,
    alg_sym: SymmetricKeyAlgorithm,
    fingerprint: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let param = build_ecdh_param(&curve.oid(), alg_sym, hash, fingerprint);

    let z = kdf(hash, shared_secret, alg_sym.key_size(), &param)?;

    let mut encrypted_session_key_vec = vec![0; encrypted_key_len];
    encrypted_session_key_vec[(encrypted_key_len - encrypted_session_key.len())..]
        .copy_from_slice(encrypted_session_key);

    let mut decrypted_key_padded = aes_kw::unwrap(&z, &encrypted_session_key_vec)?;

    {
        let len = decrypted_key_padded.len();
        let block_size = 8;
        ensure!(len % block_size == 0, "invalid key length {}", len);
        ensure!(!decrypted_key_padded.is_empty(), "empty key is not valid");

        let pad = decrypted_key_padded.last().expect("is not empty");

        if *pad as usize > len {
            return Err(Error::UnpadError);
        }

        let unpadded_len = len - *pad as usize;

        if decrypted_key_padded[unpadded_len..]
            .iter()
            .any(|byte| byte != pad)
        {
            return Err(Error::UnpadError);
        }

        decrypted_key_padded.truncate(unpadded_len);
    }

    let decrypted_key = decrypted_key_padded;
    ensure!(!decrypted_key.is_empty(), "empty unpadded key is not valid");

    Ok(decrypted_key)
}

pub fn build_ecdh_param(
    oid: &[u8],
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
) -> Vec<u8> {
    let kdf_params = vec![0x03, 0x01, hash.into(), u8::from(alg_sym)];

    let oid_len = [oid.len() as u8];

    let pkalgo = [u8::from(PublicKeyAlgorithm::ECDH)];

    let values: Vec<&[u8]> = vec![
        &oid_len,
        oid,
        &pkalgo,
        &kdf_params,
        &ANON_SENDER[..],
        fingerprint,
    ];

    values.concat()
}

pub fn kdf(hash: HashAlgorithm, x: &[u8], length: usize, param: &[u8]) -> Result<Vec<u8>> {
    let prefix = vec![0, 0, 0, 1];

    let values: Vec<&[u8]> = vec![&prefix, x, param];
    let data = values.concat();

    let mut digest = hash.digest(&data)?;
    digest.truncate(length);

    Ok(digest)
}

fn pad(plain: &[u8]) -> Vec<u8> {
    let len = plain.len();

    let remainder = len % 8;
    let padded_len = len + 8 - remainder;
    debug_assert!(
        padded_len.is_multiple_of(8),
        "Unexpected padded_len {padded_len}"
    );

    let padding = padded_len - len;
    debug_assert!(
        padding > 0 && u8::try_from(padding).is_ok(),
        "Unexpected padding value {padding}"
    );
    let padding = padding as u8;

    let mut plain_padded = plain.to_vec();
    plain_padded.resize(padded_len, padding);

    plain_padded
}

pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
    params: &EcdhPublicParams,
    fingerprint: &[u8],
    plain: &[u8],
) -> Result<PkeskBytes> {
    debug!("ECDH encrypt");

    const MAX_SIZE: usize = 239;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    let (encoded_public, shared_secret, hash, alg_sym) = match params {
        EcdhPublicParams::Curve25519Legacy {
            p,
            hash,
            alg_sym,
            ecdh_kdf_type,
        } => {
            ensure_eq!(
                ecdh_kdf_type,
                &EcdhKdfType::Native,
                "ecdh_kdf_type must be Native"
            );

            let their_public = p;
            let mut our_secret_key_bytes =
                Zeroizing::new([0u8; ECCCurve::Curve25519Legacy.secret_key_length()]);
            rng.fill_bytes(&mut *our_secret_key_bytes);
            let our_secret = StaticSecret::from(*our_secret_key_bytes);

            let shared_secret = our_secret.diffie_hellman(their_public);

            let mut encoded_public = Vec::with_capacity(33);
            encoded_public.push(0x40);
            encoded_public.extend(x25519_dalek::PublicKey::from(&our_secret).as_bytes().iter());

            (
                encoded_public,
                shared_secret.as_bytes().to_vec(),
                hash,
                alg_sym,
            )
        }

        _ => unsupported_err!("{:?} for ECDH", params),
    };

    ensure!(
        *hash != HashAlgorithm::Md5
            && *hash != HashAlgorithm::Sha1
            && *hash != HashAlgorithm::Ripemd160,
        "{:?} is not a legal hash function for ECDH KDF",
        hash
    );

    let param = build_ecdh_param(&params.curve().oid(), *alg_sym, *hash, fingerprint);

    let z = kdf(*hash, &shared_secret, alg_sym.key_size(), &param)?;

    let plain_padded = pad(plain);

    let encrypted_session_key = aes_kw::wrap(&z, &plain_padded)?;

    Ok(PkeskBytes::Ecdh {
        public_point: Mpi::from_slice(&encoded_public),
        encrypted_session_key: encrypted_session_key.into(),
    })
}
