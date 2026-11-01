use std::{io::BufRead, str};

use log::{debug, warn};
use smallvec::SmallVec;

use super::{KeyFlags, Signature, SignatureType, SignatureVersion};
use crate::{
    crypto::{
        aead::AeadAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors::{bail, ensure, ensure_eq, format_err, unsupported_err, Result},
    packet::{
        Notation, PacketHeader, RevocationCode, Subpacket, SubpacketData, SubpacketLength,
        SubpacketType,
    },
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{
        CompressionAlgorithm, Fingerprint, KeyId, KeyVersion, Mpi, PacketHeaderVersion,
        PacketLength, RevocationKey, SignatureBytes, Tag,
    },
};

impl Signature {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut i: B) -> Result<Self> {
        Self::try_from_reader_inner(packet_header, &mut i, false)
    }

    fn try_from_reader_inner<B: BufRead>(
        packet_header: PacketHeader,
        mut i: B,
        is_embedded: bool,
    ) -> Result<Self> {
        let version = i.read_u8().map(SignatureVersion::from)?;

        let signature = match version {
            SignatureVersion::V2 | SignatureVersion::V3 => v3_parser(packet_header, version, i)?,
            SignatureVersion::V4 => v4_parser(packet_header, version, i, is_embedded)?,
            SignatureVersion::V6 => v6_parser(packet_header, i, is_embedded)?,
            _ => {
                let rest = i.rest()?.freeze();
                Signature::unknown(packet_header, version, rest)
            }
        };

        Ok(signature)
    }
}

fn v3_parser<B: BufRead>(
    packet_header: PacketHeader,
    version: SignatureVersion,
    mut i: B,
) -> Result<Signature> {
    i.read_tag(&[5])?;

    let typ = i.read_u8().map(SignatureType::from)?;

    let created = i.read_timestamp()?;

    let issuer = i.read_arr::<8>().map(KeyId::from)?;

    let pub_alg = i.read_u8().map(PublicKeyAlgorithm::from)?;

    let hash_alg = i.read_u8().map(HashAlgorithm::from)?;

    let ls_hash = i.read_arr::<2>()?;

    let sig = actual_signature(&pub_alg, &mut i)?;
    debug!("signature data {sig:?}");

    match version {
        SignatureVersion::V2 => Ok(Signature::v2(
            packet_header,
            typ,
            pub_alg,
            hash_alg,
            created,
            issuer,
            ls_hash,
            sig,
        )),
        SignatureVersion::V3 => Ok(Signature::v3(
            packet_header,
            typ,
            pub_alg,
            hash_alg,
            created,
            issuer,
            ls_hash,
            sig,
        )),
        _ => unreachable!("must only be called for V2/V3"),
    }
}

fn v4_parser<B: BufRead>(
    packet_header: PacketHeader,
    version: SignatureVersion,
    mut i: B,
    is_embedded: bool,
) -> Result<Signature> {
    debug_assert_eq!(version, SignatureVersion::V4);

    let typ = i.read_u8().map(SignatureType::from)?;

    if is_embedded {
        ensure_eq!(
            typ,
            SignatureType::KeyBinding,
            "Illegal signature type {:?} in embedded signature",
            typ
        );
    }

    let pub_alg = i.read_u8().map(PublicKeyAlgorithm::from)?;

    let hash_alg = i.read_u8().map(HashAlgorithm::from)?;

    let hsub_len: usize = i.read_be_u16()?.into();
    let hsub_raw = i.read_take(hsub_len);
    let hsub = subpackets(packet_header.version(), hsub_len, hsub_raw, is_embedded)?;
    debug!(
        "found {} hashed subpackets in {} bytes",
        hsub.len(),
        hsub_len
    );

    let usub_len: usize = i.read_be_u16()?.into();
    let usub_raw = i.read_take(usub_len);
    let usub = subpackets(packet_header.version(), usub_len, usub_raw, is_embedded)?;
    debug!(
        "found {} unhashed subpackets in {} bytes",
        usub.len(),
        usub_len
    );

    let ls_hash = i.read_arr::<2>()?;

    let sig = actual_signature(&pub_alg, i)?;
    debug!("signature data {sig:?}");

    Ok(Signature::v4(
        packet_header,
        typ,
        pub_alg,
        hash_alg,
        ls_hash,
        sig,
        hsub,
        usub,
    ))
}

fn v6_parser<B: BufRead>(
    packet_header: PacketHeader,
    mut i: B,
    is_embedded: bool,
) -> Result<Signature> {
    let typ = i.read_u8().map(SignatureType::from)?;

    if is_embedded {
        ensure_eq!(
            typ,
            SignatureType::KeyBinding,
            "Illegal signature type {:?} in embedded signature",
            typ
        );
    }

    let pub_alg = i.read_u8().map(PublicKeyAlgorithm::from)?;

    let hash_alg = i.read_u8().map(HashAlgorithm::from)?;

    let hsub_len: usize = i.read_be_u32()?.try_into()?;
    let hsub_raw = i.read_take(hsub_len);
    let hsub = subpackets(packet_header.version(), hsub_len, hsub_raw, is_embedded)?;
    debug!(
        "found {} hashed subpackets in {} bytes",
        hsub.len(),
        hsub_len
    );

    let usub_len: usize = i.read_be_u32()?.try_into()?;
    let usub_raw = i.read_take(usub_len);
    let usub = subpackets(packet_header.version(), usub_len, usub_raw, is_embedded)?;
    debug!(
        "found {} unhashed subpackets in {} bytes",
        usub.len(),
        usub_len
    );

    let ls_hash = i.read_arr::<2>()?;

    let salt_len = i.read_u8()?;
    let salt = i.take_bytes(salt_len.into())?;

    if hash_alg.salt_len() != Some(salt.len()) {
        bail!(
            "Illegal salt length {} found for {:?}",
            salt.len(),
            hash_alg
        );
    }

    let sig = actual_signature(&pub_alg, i)?;
    debug!("signature data {sig:?}");
    Ok(Signature::v6(
        packet_header,
        typ,
        pub_alg,
        hash_alg,
        ls_hash,
        sig,
        hsub,
        usub,
        salt.to_vec(),
    ))
}

fn subpackets<B: BufRead>(
    packet_version: PacketHeaderVersion,
    len: usize,
    mut i: B,
    is_embedded: bool,
) -> Result<Vec<Subpacket>> {
    let mut packets = Vec::with_capacity(len.min(32));

    while i.has_remaining()? {
        let packet_len = SubpacketLength::try_from_reader(&mut i)?;
        ensure!(!packet_len.is_empty(), "empty subpacket is not allowed");

        let (typ, is_critical) = i.read_u8().map(SubpacketType::from_u8)?;
        let len = packet_len.len() - 1;
        debug!("reading subpacket {typ:?}: critical? {is_critical}, len: {len}");

        let mut body = i.read_take(len);
        let packet = subpacket(
            typ,
            is_critical,
            packet_len,
            packet_version,
            &mut body,
            is_embedded,
        )?;
        debug!("found subpacket {packet:?}");

        if !body.rest()?.is_empty() {
            warn!("failed to fully process subpacket: {typ:?}");
            if is_critical {
                bail!("invalid subpacket: {:?}", typ);
            }
        }
        packets.push(packet);
    }
    Ok(packets)
}

fn subpacket<B: BufRead>(
    typ: SubpacketType,
    is_critical: bool,
    packet_len: SubpacketLength,
    packet_version: PacketHeaderVersion,
    mut body: B,
    is_embedded: bool,
) -> Result<Subpacket> {
    use super::subpacket::SubpacketType::*;

    debug!("parsing subpacket: {typ:?}");

    let res = match typ {
        SignatureCreationTime => signature_creation_time(&mut body),
        SignatureExpirationTime => signature_expiration_time(&mut body),
        ExportableCertification => exportable_certification(&mut body),
        TrustSignature => trust_signature(&mut body),
        RegularExpression => regular_expression(&mut body),
        Revocable => revocable(&mut body),
        KeyExpirationTime => key_expiration(&mut body),
        PreferredSymmetricAlgorithms => pref_sym_alg(&mut body),
        RevocationKey => revocation_key(&mut body),
        IssuerKeyId => issuer(&mut body),
        Notation => notation_data(&mut body),
        PreferredHashAlgorithms => pref_hash_alg(&mut body),
        PreferredCompressionAlgorithms => pref_com_alg(&mut body),
        KeyServerPreferences => key_server_prefs(&mut body),
        PreferredKeyServer => preferred_key_server(&mut body),
        PrimaryUserId => primary_userid(&mut body),
        PolicyURI => policy_uri(&mut body),
        KeyFlags => key_flags(&mut body),
        SignersUserID => signers_userid(&mut body),
        RevocationReason => rev_reason(&mut body),
        Features => features(&mut body),
        SignatureTarget => sig_target(&mut body),
        EmbeddedSignature => {
            ensure!(
                !is_embedded,
                "Encountered nested embedded signature subpacket"
            );
            embedded_sig(packet_version, &mut body)
        }
        IssuerFingerprint => issuer_fingerprint(&mut body),
        PreferredEncryptionModes => preferred_encryption_modes(&mut body),
        IntendedRecipientFingerprint => intended_recipient_fingerprint(&mut body),
        PreferredAead => pref_aead_alg(&mut body),
        Experimental(n) => Ok(SubpacketData::Experimental(n, body.rest()?.freeze())),
        Other(n) => Ok(SubpacketData::Other(n, body.rest()?.freeze())),
    };

    let res = res.map(|data| Subpacket {
        is_critical,
        data,
        len: packet_len,
    });

    if res.is_err() {
        warn!("invalid subpacket: {typ:?} {res:?}");
    }

    if let Ok(subpacket) = &res {
        ensure_eq!(
            packet_len.len(),
            subpacket.data.write_len() + 1,
            "Inconsistent subpacket length {} (read {} bytes of subpacket data)",
            packet_len.len(),
            subpacket.data.write_len()
        );
    }

    if body.has_remaining()? {
        bail!(
            "Inconsistent subpacket length {} (not fully consumed)",
            packet_len.len()
        );
    }

    res
}

fn actual_signature<B: BufRead>(typ: &PublicKeyAlgorithm, mut i: B) -> Result<SignatureBytes> {
    match typ {
        PublicKeyAlgorithm::RSA | &PublicKeyAlgorithm::RSASign => {
            let v = Mpi::try_from_reader(&mut i)?;
            Ok(SignatureBytes::Mpis(vec![v]))
        }
        PublicKeyAlgorithm::DSA | PublicKeyAlgorithm::ECDSA | &PublicKeyAlgorithm::EdDSALegacy => {
            let a = Mpi::try_from_reader(&mut i)?;
            let b = Mpi::try_from_reader(&mut i)?;

            Ok(SignatureBytes::Mpis(vec![a, b]))
        }

        &PublicKeyAlgorithm::Ed25519 => {
            let sig = i.take_bytes(64)?;
            Ok(SignatureBytes::Native(sig.freeze()))
        }

        &PublicKeyAlgorithm::Elgamal => {
            let a = Mpi::try_from_reader(&mut i)?;
            let b = Mpi::try_from_reader(&mut i)?;
            Ok(SignatureBytes::Mpis(vec![a, b]))
        }
        &PublicKeyAlgorithm::Private100
        | &PublicKeyAlgorithm::Private101
        | &PublicKeyAlgorithm::Private102
        | &PublicKeyAlgorithm::Private103
        | &PublicKeyAlgorithm::Private104
        | &PublicKeyAlgorithm::Private105
        | &PublicKeyAlgorithm::Private106
        | &PublicKeyAlgorithm::Private107
        | &PublicKeyAlgorithm::Private108
        | &PublicKeyAlgorithm::Private109
        | &PublicKeyAlgorithm::Private110 => {
            let v = Mpi::try_from_reader(&mut i)?;
            Ok(SignatureBytes::Mpis(vec![v]))
        }
        PublicKeyAlgorithm::ElgamalEncrypt => {
            bail!("invalid signature algorithm, encryption only elgamal");
        }

        _ => {
            let rest = i.rest()?.freeze();
            Ok(SignatureBytes::Native(rest))
        }
    }
}

fn signature_creation_time<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let created = i.read_timestamp()?;

    Ok(SubpacketData::SignatureCreationTime(created))
}

fn issuer<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let key_id = i.read_arr::<8>().map(KeyId::from)?;

    Ok(SubpacketData::IssuerKeyId(key_id))
}

fn key_expiration<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let duration = i.read_duration()?;

    Ok(SubpacketData::KeyExpirationTime(duration))
}

fn pref_sym_alg<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[SymmetricKeyAlgorithm; 8]>::new();
    while i.has_remaining()? {
        let alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
        list.push(alg);
    }

    Ok(SubpacketData::PreferredSymmetricAlgorithms(list))
}

fn pref_aead_alg<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>::new();
    while i.has_remaining()? {
        let alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
        let aead = i.read_u8().map(AeadAlgorithm::from)?;
        list.push((alg, aead));
    }

    Ok(SubpacketData::PreferredAeadAlgorithms(list))
}

fn pref_hash_alg<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[HashAlgorithm; 8]>::new();
    while i.has_remaining()? {
        let alg = i.read_u8().map(HashAlgorithm::from)?;
        list.push(alg);
    }

    Ok(SubpacketData::PreferredHashAlgorithms(list))
}

fn pref_com_alg<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[CompressionAlgorithm; 8]>::new();
    while i.has_remaining()? {
        let alg = i.read_u8().map(CompressionAlgorithm::from)?;
        list.push(alg);
    }

    Ok(SubpacketData::PreferredCompressionAlgorithms(list))
}

fn signature_expiration_time<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let duration = i.read_duration()?;

    Ok(SubpacketData::SignatureExpirationTime(duration))
}

fn exportable_certification<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let is_exportable = i.read_u8()? == 1;

    Ok(SubpacketData::ExportableCertification(is_exportable))
}

fn revocable<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let is_revocable = i.read_u8()? == 1;

    Ok(SubpacketData::Revocable(is_revocable))
}

fn trust_signature<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let depth = i.read_u8()?;
    let value = i.read_u8()?;

    Ok(SubpacketData::TrustSignature(depth, value))
}

fn regular_expression<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let regex = i.rest()?.freeze();

    Ok(SubpacketData::RegularExpression(regex))
}

fn revocation_key<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let class = i
        .read_u8()?
        .try_into()
        .map_err(|e| format_err!("invalid revocation class: {:?}", e))?;
    let algorithm = i.read_u8().map(PublicKeyAlgorithm::from)?;

    let fp = i.read_arr::<20>()?;
    let key = RevocationKey::new(class, algorithm, &fp);

    Ok(SubpacketData::RevocationKey(key))
}

fn notation_data<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let readable = i.read_u8().map(|v| v == 0x80)?;
    i.read_tag(&[0, 0, 0])?;
    let name_len = i.read_be_u16()?;
    let value_len = i.read_be_u16()?;
    let name = i.take_bytes(name_len.into())?.freeze();
    let value = i.take_bytes(value_len.into())?.freeze();

    Ok(SubpacketData::Notation(Notation {
        readable,
        name,
        value,
    }))
}

fn key_server_prefs<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let prefs = SmallVec::from_slice(&i.rest()?);

    Ok(SubpacketData::KeyServerPreferences(prefs))
}

fn preferred_key_server<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let body = i.rest()?;
    let body_str = str::from_utf8(&body)?;

    Ok(SubpacketData::PreferredKeyServer(body_str.to_string()))
}

fn primary_userid<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let is_primary = i.read_u8()? == 1;

    Ok(SubpacketData::IsPrimary(is_primary))
}

fn policy_uri<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let body = i.rest()?;
    let body_str = str::from_utf8(&body)?;

    Ok(SubpacketData::PolicyURI(body_str.to_string()))
}

fn key_flags<B: BufRead>(i: B) -> Result<SubpacketData> {
    let flags = KeyFlags::try_from_reader(i)?;

    Ok(SubpacketData::KeyFlags(flags))
}

fn signers_userid<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let userid = i.rest()?.freeze();

    Ok(SubpacketData::SignersUserID(userid))
}

fn rev_reason<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let code = i.read_u8().map(RevocationCode::from)?;
    let reason = i.rest()?.freeze();

    Ok(SubpacketData::RevocationReason(code, reason))
}

fn features<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let features = i.rest()?;

    Ok(SubpacketData::Features(features.as_ref().into()))
}

fn sig_target<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let pub_alg = i.read_u8().map(PublicKeyAlgorithm::from)?;
    let hash_alg = i.read_u8().map(HashAlgorithm::from)?;
    let hash = i.rest()?.freeze();

    Ok(SubpacketData::SignatureTarget(pub_alg, hash_alg, hash))
}

fn embedded_sig<B: BufRead>(
    packet_version: PacketHeaderVersion,
    mut i: B,
) -> Result<SubpacketData> {
    let signature_bytes = i.rest()?.freeze();
    let header = PacketHeader::from_parts(
        packet_version,
        Tag::Signature,
        PacketLength::Fixed(signature_bytes.len().try_into()?),
    )?;
    let sig = Signature::try_from_reader_inner(header, &signature_bytes[..], true)?;

    #[cfg(feature = "malformed-artifact-compat")]
    if signature_bytes.len() != sig.write_len() {
        warn!(
            "keeping embedded signature as opaque subpacket: declared length {}, re-serializes to {}",
            signature_bytes.len(),
            sig.write_len()
        );
        return Ok(SubpacketData::Other(
            SubpacketType::EmbeddedSignature.as_u8(false),
            signature_bytes,
        ));
    }

    Ok(SubpacketData::EmbeddedSignature(Box::new(sig)))
}

fn issuer_fingerprint<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let version = i.read_u8().map(KeyVersion::from)?;

    if version != KeyVersion::V4 && version != KeyVersion::V5 && version != KeyVersion::V6 {
        unsupported_err!("invalid key version {version:?}");
    }

    if let Some(fingerprint_len) = version.fingerprint_len() {
        let fingerprint = i.take_bytes(fingerprint_len)?;
        let fp = Fingerprint::new(version, &fingerprint)?;

        return Ok(SubpacketData::IssuerFingerprint(fp));
    }
    unsupported_err!("invalid key version {version:?}");
}

fn preferred_encryption_modes<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[AeadAlgorithm; 2]>::new();
    while i.has_remaining()? {
        let alg = i.read_u8().map(AeadAlgorithm::from)?;
        list.push(alg);
    }

    Ok(SubpacketData::PreferredEncryptionModes(list))
}

fn intended_recipient_fingerprint<B: BufRead>(mut i: B) -> Result<SubpacketData> {
    let version = i.read_u8().map(KeyVersion::from)?;

    if version != KeyVersion::V4 && version != KeyVersion::V5 && version != KeyVersion::V6 {
        unsupported_err!("invalid key version {version:?}");
    }

    if let Some(fingerprint_len) = version.fingerprint_len() {
        let fingerprint = i.take_bytes(fingerprint_len)?.freeze();
        let fp = Fingerprint::new(version, &fingerprint)?;

        return Ok(SubpacketData::IntendedRecipientFingerprint(fp));
    }
    unsupported_err!("invalid key version {version:?}");
}
