use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::{
    composed::RawSessionKey,
    crypto::{checksum, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{bail, ensure_eq, Result},
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{
        EncryptionKey, EskType, Fingerprint, KeyDetails, KeyId, KeyVersion, PkeskBytes,
        PkeskVersion, PublicParams, Tag,
    },
};

#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyEncryptedSessionKey {
    V3 {
        packet_header: PacketHeader,
        id: KeyId,
        pk_algo: PublicKeyAlgorithm,
        values: PkeskBytes,
    },

    V6 {
        packet_header: PacketHeader,
        fingerprint: Option<Fingerprint>,
        pk_algo: PublicKeyAlgorithm,
        values: PkeskBytes,
    },

    Other {
        packet_header: PacketHeader,
        #[debug("{:X}", version)]
        version: u8,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

impl PublicKeyEncryptedSessionKey {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut i: B) -> Result<Self> {
        ensure_eq!(
            packet_header.tag(),
            Tag::PublicKeyEncryptedSessionKey,
            "invalid tag"
        );

        let version = i.read_u8()?;

        match version {
            3 => {
                let key_id_raw = i.read_arr::<8>()?;
                let key_id = KeyId::from(key_id_raw);

                let pk_algo = i.read_u8().map(PublicKeyAlgorithm::from)?;

                let values = PkeskBytes::try_from_reader(&pk_algo, version, &mut i)?;

                Ok(PublicKeyEncryptedSessionKey::V3 {
                    packet_header,
                    id: key_id,
                    pk_algo,
                    values,
                })
            }
            6 => {
                let len = i.read_u8()?;

                let fingerprint = match len {
                    0 => None,
                    _ => {
                        let v = i.read_u8().map(KeyVersion::from)?;

                        let fp = i.take_bytes((len - 1).into())?;
                        let fp = Fingerprint::new(v, &fp)?;

                        Some(fp)
                    }
                };

                let pk_algo = i.read_u8().map(PublicKeyAlgorithm::from)?;

                let values = PkeskBytes::try_from_reader(&pk_algo, version, &mut i)?;

                Ok(PublicKeyEncryptedSessionKey::V6 {
                    packet_header,
                    fingerprint,
                    pk_algo,
                    values,
                })
            }
            _ => {
                let data = i.rest()?.freeze();
                Ok(PublicKeyEncryptedSessionKey::Other {
                    packet_header,
                    version,
                    data,
                })
            }
        }
    }

    fn prepare_session_key_for_encryption(
        alg: Option<SymmetricKeyAlgorithm>,
        sk: &RawSessionKey,
        pp: &PublicParams,
    ) -> Zeroizing<Vec<u8>> {
        let mut data = Zeroizing::new(Vec::with_capacity(1 + sk.len() + 2));

        if let Some(alg) = alg {
            data.push(u8::from(alg));
        }

        data.extend_from_slice(sk.as_ref());

        match pp {
            PublicParams::X25519(_) => {}

            _ => data.extend_from_slice(&checksum::calculate_simple(sk.as_ref()).to_be_bytes()),
        }

        data
    }

    pub fn from_session_key_v3<R: CryptoRng + Rng, E: EncryptionKey>(
        rng: R,
        session_key: &RawSessionKey,
        alg: SymmetricKeyAlgorithm,
        enc: &E,
    ) -> Result<Self> {
        let data =
            Self::prepare_session_key_for_encryption(Some(alg), session_key, enc.public_params());

        let values = enc.encrypt(rng, &data, EskType::V3_4)?;

        let id = enc.legacy_key_id();
        let len = write_len_v3(&id, &values);
        let packet_header =
            PacketHeader::new_fixed(Tag::PublicKeyEncryptedSessionKey, len.try_into()?);

        Ok(PublicKeyEncryptedSessionKey::V3 {
            packet_header,
            id,
            pk_algo: enc.algorithm(),
            values,
        })
    }

    pub fn from_session_key_v6<R: CryptoRng + Rng, E: EncryptionKey>(
        rng: R,
        session_key: &RawSessionKey,
        enc: &E,
    ) -> Result<Self> {
        if enc.algorithm() == PublicKeyAlgorithm::Elgamal {
            bail!("ElGamal is not a legal encryption mechanism for v6 PKESK");
        }

        let data = Self::prepare_session_key_for_encryption(None, session_key, enc.public_params());

        let values = enc.encrypt(rng, &data, EskType::V6)?;
        let fingerprint = Some(enc.fingerprint());

        let len = write_len_v6(&values, &fingerprint);
        let packet_header =
            PacketHeader::new_fixed(Tag::PublicKeyEncryptedSessionKey, len.try_into()?);

        Ok(PublicKeyEncryptedSessionKey::V6 {
            packet_header,
            fingerprint,
            pk_algo: enc.algorithm(),
            values,
        })
    }

    pub fn match_identity(&self, pkey: &impl KeyDetails) -> bool {
        match self {
            Self::V3 { id, .. } => id.is_wildcard() || (id == &pkey.legacy_key_id()),
            Self::V6 { fingerprint, .. } => {
                if let Some(fingerprint) = fingerprint {
                    fingerprint == &pkey.fingerprint()
                } else {
                    true
                }
            }
            _ => false,
        }
    }

    pub fn id(&self) -> Result<&KeyId> {
        match self {
            Self::V3 { id, .. } => Ok(id),
            _ => bail!("KeyID is only available for V3 PKESK"),
        }
    }

    pub fn fingerprint(&self) -> Result<Option<&Fingerprint>> {
        match self {
            Self::V6 { fingerprint, .. } => Ok(fingerprint.as_ref()),
            _ => bail!("Fingerprint is only available for V6 PKESK"),
        }
    }

    pub fn values(&self) -> Result<&PkeskBytes> {
        match self {
            Self::V3 { values, .. } | Self::V6 { values, .. } => Ok(values),
            Self::Other { version, .. } => bail!("Unsupported PKESK version {}", version),
        }
    }

    pub fn algorithm(&self) -> Result<PublicKeyAlgorithm> {
        match self {
            Self::V3 { pk_algo, .. } | Self::V6 { pk_algo, .. } => Ok(*pk_algo),
            Self::Other { .. } => bail!("PublicKeyAlgorithm unknown for {:?}", self),
        }
    }

    pub fn version(&self) -> PkeskVersion {
        match self {
            Self::V3 { .. } => PkeskVersion::V3,
            Self::V6 { .. } => PkeskVersion::V6,
            Self::Other { version, .. } => PkeskVersion::Other(*version),
        }
    }

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    pub fn forwarding_transform<K: KeyDetails>(
        &self,
        forwardee: &K,
        proxy_parameter: crate::types::ForwardingProxyParameter,
    ) -> Result<Self> {
        use crate::types::{EcdhKdfType, EcdhPublicParams, Mpi};

        let PublicKeyEncryptedSessionKey::V3 {
            packet_header,
            id,
            values,
            pk_algo,
            ..
        } = self
        else {
            bail!("Only V3 PKESK are supported right now");
        };

        ensure_eq!(
            *pk_algo,
            PublicKeyAlgorithm::ECDH,
            "PKESK algorithm is not ECDH"
        );

        let PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { ecdh_kdf_type, .. }) =
            forwardee.public_params()
        else {
            bail!("Only forwardees using ECDH/Curve25519 are supported right now");
        };

        let EcdhKdfType::Replaced {
            replacement_fingerprint,
            ..
        } = ecdh_kdf_type
        else {
            bail!("Unexpected forwardee ecdh_kdf_type {:?}", ecdh_kdf_type)
        };

        let mut values = values.clone();

        let PkeskBytes::Ecdh {
            ref mut public_point,
            ..
        } = values
        else {
            bail!("Forwarding is only supported for PKESK based on ECDH right now");
        };

        ensure_eq!(
            public_point.len(),
            33,
            "Unexpected public point length {} in PKESK",
            public_point.len()
        );
        ensure_eq!(
            public_point.as_ref().first(),
            Some(&0x40),
            "Public point in PKESK has no 0x40 prefix",
        );

        let public_point_data = &public_point.as_ref()[1..33];

        let mut forwarded_point = [0u8; 33];
        forwarded_point[0] = 0x40;
        forwarded_point[1..].copy_from_slice(&Self::transform_ecdh_ephemeral(
            public_point_data.try_into().expect("32 bytes"),
            proxy_parameter,
        )?);

        *public_point = Mpi::from_slice(&forwarded_point);

        let id = if id == &KeyId::WILDCARD {
            KeyId::WILDCARD
        } else {
            ensure_eq!(
                id.as_ref(),
                &replacement_fingerprint[12..],
                "Key ID in PKESK {:02x?} doesn't match the replacement fingerprint of the forwardee key {:02x?}",
                id.as_ref(),
                &replacement_fingerprint[12..]
            );

            forwardee.legacy_key_id()
        };

        Ok(Self::V3 {
            packet_header: *packet_header,
            id,
            pk_algo: *pk_algo,
            values,
        })
    }

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    fn transform_ecdh_ephemeral(
        eb: [u8; 32],
        k: crate::types::ForwardingProxyParameter,
    ) -> Result<[u8; 32]> {
        use curve25519_dalek::{traits::IsIdentity, MontgomeryPoint, Scalar};

        let ephemeral = MontgomeryPoint(eb);

        if (Scalar::from(8u8) * ephemeral).is_identity() {
            bail!("Ephemeral public key belongs to a small subgroup");
        }

        let k = Zeroizing::new(Scalar::from_bytes_mod_order(k.into_array()));

        let ec = (*k) * ephemeral;

        if ec.is_identity() {
            bail!("Transformed ephemeral is the identity point");
        }

        Ok(ec.to_bytes())
    }
}

impl Serialize for PublicKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version().into())?;

        let algorithm = match self {
            PublicKeyEncryptedSessionKey::V3 { id, pk_algo, .. } => {
                writer.write_all(id.as_ref())?;
                *pk_algo
            }
            PublicKeyEncryptedSessionKey::V6 {
                fingerprint,
                pk_algo,
                ..
            } => {
                match fingerprint {
                    Some(fingerprint) => {
                        let len = fingerprint.len() + 1;
                        writer.write_u8(len.try_into()?)?;

                        match fingerprint.version() {
                            Some(version) => writer.write_u8(version.into())?,
                            None => {
                                bail!("Fingerprint without version information {:?}", fingerprint)
                            }
                        }

                        writer.write_all(fingerprint.as_bytes())?;
                    }
                    _ => writer.write_u8(0)?,
                }
                *pk_algo
            }
            PublicKeyEncryptedSessionKey::Other { version, data, .. } => {
                writer.write_u8(*version)?;
                writer.write_all(data)?;
                return Ok(());
            }
        };

        writer.write_u8(algorithm.into())?;
        self.values()?.to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        match self {
            PublicKeyEncryptedSessionKey::V3 { id, values, .. } => write_len_v3(id, values),
            PublicKeyEncryptedSessionKey::V6 {
                fingerprint,
                values,
                ..
            } => write_len_v6(values, fingerprint),
            PublicKeyEncryptedSessionKey::Other { data, .. } => write_len_other(data.len()),
        }
    }
}

impl PacketTrait for PublicKeyEncryptedSessionKey {
    fn packet_header(&self) -> &PacketHeader {
        match self {
            Self::V3 { packet_header, .. }
            | Self::V6 { packet_header, .. }
            | Self::Other { packet_header, .. } => packet_header,
        }
    }
}

fn write_len_other(data_len: usize) -> usize {
    1 + 1 + data_len
}

fn write_len_v3(id: &KeyId, values: &PkeskBytes) -> usize {
    let mut sum = 1;

    sum += id.as_ref().len();
    sum += 1;
    sum += values.write_len();
    sum
}

fn write_len_v6(values: &PkeskBytes, fingerprint: &Option<Fingerprint>) -> usize {
    let mut sum = 1;

    match fingerprint {
        Some(fingerprint) => {
            sum += 1;

            match fingerprint.version() {
                Some(_) => {
                    sum += 1;
                }
                None => {
                    panic!("Fingerprint without version information {fingerprint:?}")
                }
            }

            sum += fingerprint.len();
        }
        _ => {
            sum += 1;
        }
    }
    sum += 1;
    sum += values.write_len();

    sum
}
