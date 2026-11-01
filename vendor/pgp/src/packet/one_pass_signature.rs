use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;
use log::debug;

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::{bail, Result},
    packet::{
        signature::SignatureType, InnerSignature, PacketHeader, PacketTrait, Signature,
        SignatureVersionSpecific,
    },
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{KeyId, Tag},
};

#[derive(derive_more::Debug, Clone, PartialEq, Eq)]

pub struct OnePassSignature {
    packet_header: PacketHeader,
    typ: SignatureType,
    hash_algorithm: HashAlgorithm,
    pub_algorithm: PublicKeyAlgorithm,
    last: u8,
    version_specific: OpsVersionSpecific,
}

#[derive(derive_more::Debug, Clone, PartialEq, Eq)]

pub enum OpsVersionSpecific {
    V3 {
        key_id: KeyId,
    },
    V6 {
        #[debug("{}", hex::encode(salt))]
        salt: Bytes,
        #[debug("{}", hex::encode(fingerprint))]
        fingerprint: [u8; 32],
    },

    Unknown {
        #[debug("{:X}", version)]
        version: u8,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

impl Serialize for OpsVersionSpecific {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        if let OpsVersionSpecific::V6 { salt, .. } = self {
            writer.write_u8(salt.len().try_into()?)?;
            writer.write_all(salt)?;
        }

        match self {
            OpsVersionSpecific::V3 { key_id } => {
                writer.write_all(key_id.as_ref())?;
            }
            OpsVersionSpecific::V6 { fingerprint, .. } => {
                writer.write_all(fingerprint.as_ref())?;
            }
            OpsVersionSpecific::Unknown { data, .. } => {
                writer.write_all(data)?;
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;

        if let OpsVersionSpecific::V6 { salt, .. } = self {
            sum += 1;
            sum += salt.len();
        }
        match self {
            OpsVersionSpecific::V3 { key_id } => {
                sum += key_id.as_ref().len();
            }
            OpsVersionSpecific::V6 { fingerprint, .. } => {
                sum += fingerprint.len();
            }
            OpsVersionSpecific::Unknown { data, .. } => {
                sum += data.len();
            }
        }
        sum
    }
}

impl OnePassSignature {
    pub fn version(&self) -> u8 {
        match self.version_specific {
            OpsVersionSpecific::V3 { .. } => 3,
            OpsVersionSpecific::V6 { .. } => 6,
            OpsVersionSpecific::Unknown { version, .. } => version,
        }
    }

    pub fn matches(&self, sig: &Signature) -> bool {
        let InnerSignature::Known {
            config: sig_config, ..
        } = &sig.inner
        else {
            return false;
        };

        if self.typ != sig_config.typ {
            debug!(
                "Unmatched signature type: Ops {:?}, Sig {:?}",
                self.typ, sig_config.typ
            );
            return false;
        }

        if self.hash_algorithm != sig_config.hash_alg {
            debug!(
                "Unmatched hash algorithms: Ops {:?}, Sig {:?}",
                self.hash_algorithm, sig_config.hash_alg
            );
            return false;
        }

        if self.pub_algorithm != sig_config.pub_alg {
            debug!(
                "Unmatched public key algorithms: Ops {:?}, Sig {:?}",
                self.pub_algorithm, sig_config.pub_alg
            );
            return false;
        }

        match (&self.version_specific, &sig_config.version_specific) {
            (OpsVersionSpecific::V3 { .. }, SignatureVersionSpecific::V4) => {}
            (
                OpsVersionSpecific::V6 { salt: ops_salt, .. },
                SignatureVersionSpecific::V6 { salt: sig_salt, .. },
            ) => {
                if ops_salt != sig_salt {
                    debug!(
                        "Salt mismatch between Ops and Signature: {ops_salt:02x?} / {sig_salt:02x?}"
                    );
                    return false;
                }
            }
            _ => {
                debug!("Illegal combination of Ops and Signature version: {self:?}, {sig:?}");
                return false;
            }
        }

        true
    }
}

impl OnePassSignature {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut i: B) -> Result<Self> {
        let version = i.read_u8()?;
        let typ = i.read_u8().map(SignatureType::from)?;
        let hash_algorithm = i.read_u8().map(HashAlgorithm::from)?;
        let pub_algorithm = i.read_u8().map(PublicKeyAlgorithm::from)?;

        let (version_specific, last) = match version {
            3 => {
                let key_id_raw: [u8; 8] = i.read_arr::<8>()?;

                let last = i.read_u8()?;
                (
                    OpsVersionSpecific::V3 {
                        key_id: key_id_raw.into(),
                    },
                    last,
                )
            }
            6 => {
                let salt_len = i.read_u8()?;
                let salt = i.take_bytes(salt_len.into())?.freeze();
                let fingerprint = i.read_arr::<32>()?;
                let last = i.read_u8()?;

                (OpsVersionSpecific::V6 { salt, fingerprint }, last)
            }
            _ => {
                let mut data = i.rest()?.freeze();
                let last = if !data.is_empty() {
                    let last = data.split_off(data.len() - 1);
                    last[0]
                } else {
                    bail!("missing last field");
                };
                (OpsVersionSpecific::Unknown { version, data }, last)
            }
        };

        Ok(OnePassSignature {
            packet_header,
            typ,
            hash_algorithm,
            pub_algorithm,
            last,
            version_specific,
        })
    }

    pub fn v3(
        typ: SignatureType,
        hash_algorithm: HashAlgorithm,
        pub_algorithm: PublicKeyAlgorithm,
        key_id: KeyId,
    ) -> Self {
        let version_specific = OpsVersionSpecific::V3 { key_id };
        let len = WRITE_LEN_OVERHEAD + version_specific.write_len();
        let packet_header =
            PacketHeader::new_fixed(Tag::OnePassSignature, len.try_into().expect("fixed"));

        OnePassSignature {
            packet_header,
            typ,
            hash_algorithm,
            pub_algorithm,
            last: 1,
            version_specific,
        }
    }

    pub fn v6(
        typ: SignatureType,
        hash_algorithm: HashAlgorithm,
        pub_algorithm: PublicKeyAlgorithm,
        salt: Vec<u8>,
        fingerprint: [u8; 32],
    ) -> Self {
        let version_specific = OpsVersionSpecific::V6 {
            salt: salt.into(),
            fingerprint,
        };
        let len = WRITE_LEN_OVERHEAD + version_specific.write_len();
        let packet_header =
            PacketHeader::new_fixed(Tag::OnePassSignature, len.try_into().expect("fixed"));

        OnePassSignature {
            packet_header,
            typ,
            hash_algorithm,
            pub_algorithm,
            last: 1,
            version_specific,
        }
    }

    pub fn is_nested(&self) -> bool {
        self.last == 0
    }

    pub fn set_is_nested(&mut self) {
        self.last = 0;
    }

    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    pub fn public_key_algorithm(&self) -> PublicKeyAlgorithm {
        self.pub_algorithm
    }

    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    pub fn version_specific(&self) -> &OpsVersionSpecific {
        &self.version_specific
    }
}

const WRITE_LEN_OVERHEAD: usize = 5;

impl Serialize for OnePassSignature {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version())?;
        writer.write_u8(self.typ.into())?;
        writer.write_u8(self.hash_algorithm.into())?;
        writer.write_u8(self.pub_algorithm.into())?;

        self.version_specific.to_writer(writer)?;
        writer.write_u8(self.last)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = WRITE_LEN_OVERHEAD;
        sum += self.version_specific.write_len();
        sum
    }
}

impl PacketTrait for OnePassSignature {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
