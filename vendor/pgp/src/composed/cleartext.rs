use std::{
    collections::HashSet,
    io::{BufRead, Read},
};

use buffer_redux::BufReader;
use log::debug;

use crate::{
    armor::{self, header_parser, read_from_buf, BlockType, DearmorOptions, Headers},
    composed::ArmorOptions,
    crypto::hash::HashAlgorithm,
    errors::{bail, ensure, ensure_eq, format_err, InvalidInputSnafu, Result},
    line_writer::LineBreak,
    normalize_lines::{normalize_lines, NormalizedReader},
    packet::{
        Packet, PacketParser, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData,
    },
    ser::Serialize,
    types::{KeyVersion, Password, SigningKey, Timestamp, VerifyingKey},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextSignedMessage {
    csf_encoded_text: String,

    hashes: Vec<HashAlgorithm>,

    signatures: Vec<Signature>,
}

impl CleartextSignedMessage {
    pub fn new(
        text: &str,
        config: SignatureConfig,
        key: &impl SigningKey,
        key_pw: &Password,
    ) -> Result<Self>
where {
        let mut bytes = text.as_bytes();
        let signature_text = NormalizedReader::new(&mut bytes, LineBreak::Crlf);
        let hash = config.hash_alg;
        let signature = config.sign(key, key_pw, signature_text)?;

        Ok(Self {
            csf_encoded_text: dash_escape(text),
            hashes: vec![hash],
            signatures: vec![signature],
        })
    }

    pub fn sign<R>(rng: R, text: &str, key: &impl SigningKey, key_pw: &Password) -> Result<Self>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
        ];

        let mut config = SignatureConfig::from_key(rng, key, SignatureType::Text)?;
        config.hashed_subpackets = hashed_subpackets;

        if key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                key.legacy_key_id(),
            ))?];
        }

        Self::new(text, config, key, key_pw)
    }

    pub fn new_many<F>(text: &str, signer: F) -> Result<Self>
    where
        F: FnOnce(&str) -> Result<Vec<Signature>>,
    {
        let signature_text = normalize_lines(text, LineBreak::Crlf);

        let raw_signatures = signer(&signature_text[..])?;
        let mut hashes = HashSet::new();
        let mut signatures = Vec::new();

        for signature in raw_signatures {
            let hash_alg = signature
                .hash_alg()
                .ok_or_else(|| InvalidInputSnafu {}.build())?;
            hashes.insert(hash_alg);
            signatures.push(signature);
        }

        Ok(Self {
            csf_encoded_text: dash_escape(text),
            hashes: hashes.into_iter().collect(),
            signatures,
        })
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    pub fn verify(&self, key: &impl VerifyingKey) -> Result<&Signature> {
        let nt = self.signed_text();
        for signature in &self.signatures {
            if signature.verify(key, nt.as_bytes()).is_ok() {
                return Ok(signature);
            }
        }

        bail!("No matching signature found")
    }

    pub fn verify_many<F>(&self, verifier: F) -> Result<()>
    where
        F: Fn(usize, &Signature, &[u8]) -> Result<()>,
    {
        let nt = self.signed_text();
        for (i, signature) in self.signatures.iter().enumerate() {
            verifier(i, signature, nt.as_bytes())?;
        }
        Ok(())
    }

    pub fn signed_text(&self) -> String {
        let unescaped = dash_unescape_and_trim(&self.csf_encoded_text);

        normalize_lines(&unescaped, LineBreak::Crlf).to_string()
    }

    pub fn text(&self) -> &str {
        &self.csf_encoded_text
    }

    pub fn from_armor<R: Read>(bytes: R) -> Result<(Self, Headers)> {
        Self::from_armor_buf(BufReader::new(bytes), DearmorOptions::default())
    }

    pub fn from_string(input: &str) -> Result<(Self, Headers)> {
        Self::from_armor_buf(input.as_bytes(), DearmorOptions::default())
    }

    pub fn from_armor_buf<R: BufRead>(mut b: R, opt: DearmorOptions) -> Result<(Self, Headers)> {
        debug!("parsing cleartext message");

        let (typ, headers, has_leading_data) =
            read_from_buf(&mut b, "cleartext header", opt.limit, header_parser)?;
        ensure_eq!(typ, BlockType::CleartextMessage, "unexpected block type");
        ensure!(
            !has_leading_data,
            "must not have leading data for a cleartext message"
        );

        Self::from_armor_after_header(b, headers, opt)
    }

    pub fn from_armor_after_header<R: BufRead>(
        mut b: R,
        headers: Headers,
        opt: DearmorOptions,
    ) -> Result<(Self, Headers)> {
        let hashes = validate_headers(headers)?;

        debug!("Found Hash headers: {hashes:?}");

        let (csf_encoded_text, prefix) = read_cleartext_body(&mut b)?;
        let b = std::io::Cursor::new(prefix).chain(b);

        let mut dearmor = armor::Dearmor::with_options(b, opt);
        dearmor.read_header()?;

        let typ = dearmor
            .typ
            .ok_or_else(|| format_err!("dearmor failed to retrieve armor type"))?;

        ensure_eq!(typ, BlockType::Signature, "invalid block type");

        let mut signatures = vec![];

        let pp = PacketParser::new(BufReader::new(&mut dearmor));
        for res in pp {
            match res {
                Ok(Packet::Signature(sig)) => signatures.push(sig),
                Ok(p) => bail!("unexpected packet {:?}", p),
                Err(e) => return Err(e),
            }
        }

        let (_, headers, _, b) = dearmor.into_parts();

        if has_rest(b)? {
            bail!("unexpected trailing data");
        }

        Ok((
            Self {
                csf_encoded_text,
                hashes,
                signatures,
            },
            headers,
        ))
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl std::io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        writer.write_all(HEADER_LINE.as_bytes())?;
        writer.write_all(b"\n")?;

        for hash in &self.hashes {
            writer.write_all(b"Hash: ")?;
            writer.write_all(hash.to_string().as_bytes())?;
            writer.write_all(b"\n")?;
        }
        writer.write_all(b"\n")?;

        writer.write_all(self.csf_encoded_text.as_bytes())?;
        writer.write_all(b"\n")?;

        struct SerializableSignatures<'a>(&'a [Signature]);
        impl Serialize for SerializableSignatures<'_> {
            fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
                for sig in self.0 {
                    sig.to_writer_with_header(writer)?;
                }
                Ok(())
            }

            fn write_len(&self) -> usize {
                let mut sum = 0;
                for sig in self.0 {
                    sum += sig.write_len_with_header();
                }
                sum
            }
        }

        armor::write(
            &SerializableSignatures(&self.signatures),
            armor::BlockType::Signature,
            writer,
            opts.headers,
            opts.include_checksum,
        )
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.to_armored_writer(&mut buf, opts)?;
        Ok(buf)
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> Result<String> {
        let res = String::from_utf8(self.to_armored_bytes(opts)?).map_err(|e| e.utf8_error())?;
        Ok(res)
    }
}

fn validate_headers(headers: Headers) -> Result<Vec<HashAlgorithm>> {
    let mut hashes = Vec::new();
    for (name, values) in headers {
        ensure_eq!(name, "Hash", "unexpected header");
        for value in values {
            let h: HashAlgorithm = value
                .parse()
                .map_err(|_| format_err!("unknown hash algorithm {}", value))?;
            hashes.push(h);
        }
    }
    Ok(hashes)
}

fn dash_escape(text: &str) -> String {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with('-') {
            out += "- ";
        }
        out.push_str(line);
    }

    out
}

fn dash_unescape_and_trim(text: &str) -> String {
    let mut out = String::new();

    for line in text.split_inclusive('\n') {
        let line_end_len = if line.ends_with("\r\n") {
            2
        } else if line.ends_with('\n') {
            1
        } else {
            0
        };
        let (content, end) = line.split_at(line.len() - line_end_len);

        let undashed = content.strip_prefix("- ").unwrap_or(content);

        let trimmed = undashed.trim_end_matches([' ', '\t']);

        out += trimmed;

        out += end;
    }

    out
}

fn has_rest<R: BufRead>(mut b: R) -> Result<bool> {
    let mut buf = [0u8; 64];
    while b.read(&mut buf)? > 0 {
        if buf.iter().any(|&c| !char::from(c).is_ascii_whitespace()) {
            return Ok(true);
        }
    }

    Ok(false)
}

const HEADER_LINE: &str = "-----BEGIN PGP SIGNED MESSAGE-----";

fn read_cleartext_body<B: BufRead>(b: &mut B) -> Result<(String, String)> {
    let mut out = String::new();

    loop {
        let read = b.read_line(&mut out)?;

        if read == 0 {
            bail!("unexpected early end");
        }

        if out.starts_with("-----") {
            return Ok(("".to_string(), out));
        }

        if let Some(pos) = out.rfind("\n-----") {
            let rest = out.split_off(pos + 1);

            if out.ends_with("\r\n") {
                out.truncate(out.len() - 2);
            } else {
                out.truncate(out.len() - 1);
            }
            return Ok((out, rest));
        }
    }
}
