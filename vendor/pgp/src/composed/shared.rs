use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
};

use log::{debug, warn};

use crate::{
    armor::{self, BlockType, DearmorOptions},
    errors::{bail, format_err, unimplemented_err, Error, Result},
    packet::{Packet, PacketParser},
};

pub trait Deserializable: Sized {
    fn from_bytes<R: BufRead>(bytes: R) -> Result<Self> {
        let mut el = Self::from_bytes_many(bytes)?;
        el.next()
            .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())?
    }

    fn from_string(input: &str) -> Result<(Self, armor::Headers)> {
        let (mut el, headers) = Self::from_string_many(input)?;
        Ok((
            el.next()
                .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??,
            headers,
        ))
    }

    fn from_string_many<'a>(
        input: &'a str,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>> + 'a>, armor::Headers)> {
        Self::from_armor_many_buf(input.as_bytes())
    }

    fn from_armor_single<R: Read>(input: R) -> Result<(Self, armor::Headers)> {
        let (mut el, headers) = Self::from_armor_many(input)?;
        Ok((
            el.next()
                .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??,
            headers,
        ))
    }

    fn from_armor_single_buf<R: BufRead>(input: R) -> Result<(Self, armor::Headers)> {
        Self::from_armor_single_buf_with_options(input, DearmorOptions::default())
    }

    fn from_armor_single_buf_with_options<R: BufRead>(
        input: R,
        opt: DearmorOptions,
    ) -> Result<(Self, armor::Headers)> {
        let (mut el, headers) = Self::from_armor_many_buf_with_options(input, opt)?;
        Ok((
            el.next()
                .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??,
            headers,
        ))
    }

    fn from_armor_many<'a, R: Read + 'a>(
        input: R,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>> + 'a>, armor::Headers)> {
        Self::from_armor_many_buf(BufReader::new(input))
    }

    fn from_armor_many_buf<'a, R: BufRead + 'a>(
        input: R,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>> + 'a>, armor::Headers)> {
        Self::from_armor_many_buf_with_options(input, DearmorOptions::default())
    }

    fn from_armor_many_buf_with_options<'a, R: BufRead + 'a>(
        input: R,
        opt: DearmorOptions,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>> + 'a>, armor::Headers)> {
        let mut dearmor = armor::Dearmor::with_options(input, opt);
        dearmor.read_header()?;

        let typ = dearmor
            .typ
            .ok_or_else(|| format_err!("dearmor failed to retrieve armor type"))?;

        match typ {
            BlockType::PublicKey
            | BlockType::PrivateKey
            | BlockType::Message
            | BlockType::MultiPartMessage(_, _)
            | BlockType::Signature
            | BlockType::CleartextMessage
            | BlockType::File => {
                let headers = dearmor.headers.clone();

                if !Self::matches_block_type(typ) {
                    bail!("unexpected block type: {}", typ);
                }

                Ok((Self::from_bytes_many(BufReader::new(dearmor))?, headers))
            }
            BlockType::PublicKeyPKCS1(_)
            | BlockType::PublicKeyPKCS8
            | BlockType::PublicKeyOpenssh
            | BlockType::PrivateKeyPKCS1(_)
            | BlockType::PrivateKeyPKCS8
            | BlockType::PrivateKeyOpenssh => {
                unimplemented_err!("key format {:?}", typ);
            }
        }
    }

    fn from_bytes_many<'a, R: BufRead + 'a>(
        bytes: R,
    ) -> Result<Box<dyn Iterator<Item = Result<Self>> + 'a>> {
        let packets = PacketParser::new(bytes)
            .filter_map(crate::composed::shared::filter_parsed_packet_results)
            .peekable();

        Ok(Self::from_packets(packets))
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut el = Self::from_file_many(path)?;
        el.next()
            .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())?
    }

    fn from_armor_file<P: AsRef<Path>>(path: P) -> Result<(Self, armor::Headers)> {
        let (mut el, headers) = Self::from_armor_file_many(path)?;
        let el = el
            .next()
            .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??;
        Ok((el, headers))
    }

    fn from_armor_file_many<P: AsRef<Path>>(
        path: P,
    ) -> Result<(Box<dyn Iterator<Item = Result<Self>>>, armor::Headers)> {
        let file = std::fs::File::open(path)?;
        Self::from_armor_many_buf(BufReader::new(file))
    }

    fn from_file_many<P: AsRef<Path>>(path: P) -> Result<Box<dyn Iterator<Item = Result<Self>>>> {
        let file = std::fs::File::open(path)?;
        Self::from_bytes_many(BufReader::new(file))
    }

    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a>;

    fn matches_block_type(typ: BlockType) -> bool;

    fn from_reader_single<'a, R: Read + 'a>(input: R) -> Result<(Self, Option<armor::Headers>)> {
        Self::from_reader_single_buf(BufReader::new(input))
    }

    fn from_reader_single_buf<'a, R: BufRead + 'a>(
        mut input: R,
    ) -> Result<(Self, Option<armor::Headers>)> {
        if !is_binary(&mut input)? {
            let (keys, headers) = Self::from_armor_single(input)?;
            Ok((keys, Some(headers)))
        } else {
            let (mut el, headers) = Self::from_reader_many_buf(input)?;
            let packet = el
                .next()
                .ok_or_else(|| crate::errors::NoMatchingPacketSnafu.build())??;
            Ok((packet, headers))
        }
    }

    fn from_reader_many<'a, R: Read + 'a>(
        input: R,
    ) -> Result<(
        Box<dyn Iterator<Item = Result<Self>> + 'a>,
        Option<armor::Headers>,
    )> {
        Self::from_reader_many_buf(BufReader::new(input))
    }

    fn from_reader_many_buf<'a, R: BufRead + 'a>(
        mut input: R,
    ) -> Result<(
        Box<dyn Iterator<Item = Result<Self>> + 'a>,
        Option<armor::Headers>,
    )> {
        if !is_binary(&mut input)? {
            let (keys, headers) = Self::from_armor_many_buf(input)?;
            Ok((keys, Some(headers)))
        } else {
            Ok((Self::from_bytes_many(input)?, None))
        }
    }
}

pub(crate) fn filter_parsed_packet_results(p: Result<Packet>) -> Option<Result<Packet>> {
    match p {
        Ok(ref packet) => {
            if let Packet::Marker(_) = packet {
                debug!("skipping marker packet");
                return None;
            }
            if let Packet::Padding(_) = packet {
                debug!("skipping padding packet");
                return None;
            }
            Some(p)
        }
        Err(e) => {
            if let Error::Unsupported { ref message, .. } = e {
                warn!("skipping unsupported packet: {e:?}");
                debug!("error: {message}");
                return None;
            }
            if let Error::InvalidPacketContent { ref source } = &e {
                let err: &Error = source;
                if let Error::Unsupported { message, .. } = err {
                    warn!("skipping unsupported packet: {e:?}");
                    debug!("error: {message}");
                    return None;
                }
            }
            if let Error::PacketIncomplete { ref source, .. } = e {
                warn!("skipping incomplete packet: {e:?}");
                debug!("error: {source:?}");
                return None;
            }

            Some(Err(e))
        }
    }
}

pub(crate) fn is_binary<R: BufRead>(input: &mut R) -> Result<bool> {
    let buf = input.fill_buf()?;
    if buf.is_empty() {
        bail!("empty input");
    }

    let binary = buf[0] & 0x80 != 0;

    Ok(binary)
}
