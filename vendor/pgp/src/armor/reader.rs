use std::{cmp::PartialEq, collections::BTreeMap, fmt, hash::Hasher, io, io::prelude::*, str};

use base64::engine::{general_purpose::STANDARD, Engine as _};
use buffer_redux::BufReader;
use byteorder::{BigEndian, ByteOrder};
use nom::{
    branch::alt,
    bytes::streaming::{tag, take, take_until, take_until1},
    character::streaming::{digit1, line_ending, not_line_ending, space0},
    combinator::{complete, map, map_res, opt, success, value},
    multi::many0,
    sequence::{delimited, pair, preceded, terminated},
    AsChar, IResult, Input, Parser,
};

use crate::{
    base64::{Base64Decoder, Base64Reader},
    errors::{bail, Result},
    ser::Serialize,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum BlockType {
    PublicKey,
    PublicKeyPKCS1(PKCS1Type),
    PublicKeyPKCS8,
    PublicKeyOpenssh,
    PrivateKey,
    PrivateKeyPKCS1(PKCS1Type),
    PrivateKeyPKCS8,
    PrivateKeyOpenssh,
    Message,
    MultiPartMessage(usize, usize),
    Signature,

    File,
    CleartextMessage,
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockType::PublicKey => f.write_str("PGP PUBLIC KEY BLOCK"),
            BlockType::PrivateKey => f.write_str("PGP PRIVATE KEY BLOCK"),
            BlockType::MultiPartMessage(x, y) => write!(f, "PGP MESSAGE, PART {x}/{y}"),
            BlockType::Message => f.write_str("PGP MESSAGE"),
            BlockType::Signature => f.write_str("PGP SIGNATURE"),
            BlockType::File => f.write_str("PGP ARMORED FILE"),
            BlockType::PublicKeyPKCS1(typ) => write!(f, "{typ} PUBLIC KEY"),
            BlockType::PublicKeyPKCS8 => f.write_str("PUBLIC KEY"),
            BlockType::PublicKeyOpenssh => f.write_str("OPENSSH PUBLIC KEY"),
            BlockType::PrivateKeyPKCS1(typ) => write!(f, "{typ} PRIVATE KEY"),
            BlockType::PrivateKeyPKCS8 => f.write_str("PRIVATE KEY"),
            BlockType::PrivateKeyOpenssh => f.write_str("OPENSSH PRIVATE KEY"),
            BlockType::CleartextMessage => f.write_str("PGP SIGNED MESSAGE"),
        }
    }
}

impl Serialize for BlockType {
    fn to_writer<W: io::Write>(&self, w: &mut W) -> Result<()> {
        write!(w, "{self}")?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let x = self.to_string();
        x.len()
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PKCS1Type {
    RSA,
    DSA,
    EC,
}

impl fmt::Display for PKCS1Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PKCS1Type::RSA => write!(f, "RSA"),
            PKCS1Type::DSA => write!(f, "DSA"),
            PKCS1Type::EC => write!(f, "EC"),
        }
    }
}

pub type Headers = BTreeMap<String, Vec<String>>;

fn armor_header_sep(i: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(&b"-----"[..])(i)
}

#[inline]
fn parse_digit(x: &[u8]) -> Result<usize> {
    let s = str::from_utf8(x)?;
    let digit: usize = s.parse()?;
    Ok(digit)
}

fn armor_header_type(i: &[u8]) -> IResult<&[u8], BlockType> {
    alt((
        value(BlockType::PublicKey, tag("PGP PUBLIC KEY BLOCK")),
        value(BlockType::PrivateKey, tag("PGP PRIVATE KEY BLOCK")),
        map(
            preceded(
                tag("PGP MESSAGE, PART "),
                pair(
                    map_res(digit1, parse_digit),
                    opt(preceded(tag("/"), map_res(digit1, parse_digit))),
                ),
            ),
            |(x, y)| BlockType::MultiPartMessage(x, y.unwrap_or(0)),
        ),
        value(BlockType::Message, tag("PGP MESSAGE")),
        value(BlockType::Signature, tag("PGP SIGNATURE")),
        value(BlockType::File, tag("PGP ARMORED FILE")),
        value(BlockType::CleartextMessage, tag("PGP SIGNED MESSAGE")),
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::RSA),
            tag("RSA PUBLIC KEY"),
        ),
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::DSA),
            tag("DSA PUBLIC KEY"),
        ),
        value(
            BlockType::PublicKeyPKCS1(PKCS1Type::EC),
            tag("EC PUBLIC KEY"),
        ),
        value(BlockType::PublicKeyPKCS8, tag("PUBLIC KEY")),
        value(BlockType::PublicKeyOpenssh, tag("OPENSSH PUBLIC KEY")),
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::RSA),
            tag("RSA PRIVATE KEY"),
        ),
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::DSA),
            tag("DSA PRIVATE KEY"),
        ),
        value(
            BlockType::PrivateKeyPKCS1(PKCS1Type::EC),
            tag("EC PRIVATE KEY"),
        ),
        value(BlockType::PrivateKeyPKCS8, tag("PRIVATE KEY")),
        value(BlockType::PrivateKeyOpenssh, tag("OPENSSH PRIVATE KEY")),
    ))
    .parse(i)
}

fn armor_header_line(i: &[u8]) -> IResult<&[u8], BlockType> {
    delimited(
        pair(armor_header_sep, tag(&b"BEGIN "[..])),
        armor_header_type,
        pair(armor_header_sep, line_ending),
    )
    .parse(i)
}

fn key_value_pair(i: &[u8]) -> IResult<&[u8], (&str, &str)> {
    let (i, key) = map_res(
        alt((
            complete(take_until1(":\r\n")),
            complete(take_until1(":\n")),
            complete(take_until1(": ")),
        )),
        str::from_utf8,
    )
    .parse(i)?;

    let (i, _) = tag(":")(i)?;
    let (i, t) = alt((tag(" "), line_ending)).parse(i)?;

    let (i, value) = if t == b" " {
        let (i, value) = map_res(not_line_ending, str::from_utf8).parse(i)?;
        let (i, _) = line_ending(i)?;
        (i, value)
    } else {
        (i, "")
    };

    Ok((i, (key, value)))
}

fn key_value_pairs(i: &[u8]) -> IResult<&[u8], Vec<(&str, &str)>> {
    many0(complete(key_value_pair)).parse(i)
}

fn armor_headers(i: &[u8]) -> IResult<&[u8], Headers> {
    map(key_value_pairs, |pairs| {
        let mut out = BTreeMap::<String, Vec<String>>::new();
        for (k, v) in pairs {
            let e = out.entry(k.to_string()).or_default();
            e.push(v.to_string());
        }
        out
    })
    .parse(i)
}

fn armor_header(i: &[u8]) -> IResult<&[u8], (BlockType, Headers)> {
    let (i, typ) = armor_header_line(i)?;
    let (i, headers) = match typ {
        BlockType::CleartextMessage => armor_headers_hash(i)?,
        _ => armor_headers(i)?,
    };

    Ok((i, (typ, headers)))
}

fn armor_headers_hash(i: &[u8]) -> IResult<&[u8], Headers> {
    let (i, headers) = many0(complete(hash_header_line)).parse(i)?;

    let mut res = BTreeMap::new();
    let headers = headers.into_iter().flatten().collect();
    res.insert("Hash".to_string(), headers);

    Ok((i, res))
}

pub fn alphanumeric1_or_dash<T, E: nom::error::ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: Input,
    <T as Input>::Item: AsChar,
{
    input.split_at_position1(
        |item| {
            let i = item.as_char();

            !(i.is_alphanum() || i == '-')
        },
        nom::error::ErrorKind::AlphaNumeric,
    )
}

fn hash_header_line(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let (i, _) = tag("Hash: ")(i)?;
    let (i, mut values) = many0(map_res(terminated(alphanumeric1_or_dash, tag(",")), |s| {
        str::from_utf8(s).map(|s| s.to_string())
    }))
    .parse(i)?;

    let (i, last_value) = terminated(
        map_res(alphanumeric1_or_dash, |s| {
            str::from_utf8(s).map(|s| s.to_string())
        }),
        line_ending,
    )
    .parse(i)?;
    values.push(last_value);

    Ok((i, values))
}

fn read_checksum(input: &[u8]) -> std::io::Result<u64> {
    let checksum = STANDARD
        .decode(input)
        .map_err(|_| io::ErrorKind::InvalidData)?;

    let mut buf = [0; 4];
    let mut i = checksum.len();
    for a in checksum.iter().rev() {
        buf[i] = *a;
        i -= 1;
    }

    Ok(u64::from(BigEndian::read_u32(&buf)))
}

pub fn header_parser(i: &[u8]) -> IResult<&[u8], (BlockType, Headers, bool)> {
    let (i, prefix) = take_until("-----")(i)?;
    let has_leading_data = !prefix.is_empty();

    let (i, (typ, headers)) = armor_header(i)?;

    let (i, _) = pair(space0, line_ending).parse(i)?;

    Ok((i, (typ, headers, has_leading_data)))
}

fn footer_parser(i: &[u8]) -> IResult<&[u8], (Option<u64>, BlockType)> {
    let (i, checksum) = map_res(
        alt((
            delimited(
                tag(&b"="[..]),
                map(take(4u8), Some),
                pair(many0(line_ending), tag(&b"--"[..])),
            ),
            delimited(
                many0(tag(&b"="[..])),
                success(None),
                pair(many0(line_ending), tag(&b"--"[..])),
            ),
        )),
        |c| c.map(read_checksum).transpose(),
    )
    .parse(i)?;
    let (i, typ) = armor_footer_line(i)?;

    Ok((i, (checksum, typ)))
}

fn armor_footer_line(i: &[u8]) -> IResult<&[u8], BlockType> {
    delimited(
        tag(&b"---END "[..]),
        armor_header_type,
        pair(armor_header_sep, opt(complete(line_ending))),
    )
    .parse(i)
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ArmorCrc24Status {
    NoCrc24,

    CheckedOk {
        crc: u32,
    },

    CheckedInvalid {
        footer_crc: u32,
        calculated_crc: u32,
    },

    Unchecked {
        footer_crc: u32,
    },
}

#[derive(derive_more::Debug)]
pub struct Dearmor<R: BufRead> {
    pub typ: Option<BlockType>,
    pub headers: Headers,
    pub checksum: Option<u64>,
    current_part: Part<R>,
    #[debug("Crc24Hasher")]
    crc: Option<crc24::Crc24Hasher>,
    max_buffer_limit: usize,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Part<R: BufRead> {
    Header(R),
    Body(Base64Decoder<Base64Reader<R>>),
    Footer(BufReader<R>),
    Done(BufReader<R>),
    Temp,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct DearmorOptions {
    pub(crate) limit: usize,
    pub(crate) crc24_check: bool,
}

impl DearmorOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    pub fn enable_crc24_check(mut self) -> Self {
        self.crc24_check = true;
        self
    }
}

impl Default for DearmorOptions {
    fn default() -> Self {
        Self {
            limit: 1024 * 1024 * 1024,
            crc24_check: false,
        }
    }
}

impl<R: BufRead> Dearmor<R> {
    pub fn new(input: R) -> Self {
        Self::with_options(input, DearmorOptions::default())
    }

    pub fn with_options(input: R, opt: DearmorOptions) -> Self {
        let crc = if opt.crc24_check {
            Some(Default::default())
        } else {
            None
        };

        Dearmor {
            typ: None,
            headers: BTreeMap::new(),
            checksum: None,
            current_part: Part::Header(input),
            crc,
            max_buffer_limit: opt.limit,
        }
    }

    pub fn into_parts(self) -> (Option<BlockType>, Headers, Option<u64>, BufReader<R>) {
        let Self {
            typ,
            headers,
            checksum,
            current_part,
            ..
        } = self;
        let Part::Done(b) = current_part else {
            panic!("can only be called when done");
        };

        (typ, headers, checksum, b)
    }

    pub fn max_buffer_limit(&self) -> usize {
        self.max_buffer_limit
    }

    pub fn read_only_header(mut self) -> Result<(BlockType, Headers, bool, R)> {
        let header = std::mem::replace(&mut self.current_part, Part::Temp);
        if let Part::Header(mut b) = header {
            let (typ, headers, leading) =
                Self::read_header_internal(&mut b, self.max_buffer_limit)?;
            return Ok((typ, headers, leading, b));
        }

        bail!("invalid state, cannot read header");
    }

    pub fn after_header(typ: BlockType, headers: Headers, input: R, limit: usize) -> Self {
        Self {
            typ: Some(typ),
            headers,
            checksum: None,
            current_part: Part::Body(Base64Decoder::new(Base64Reader::new(input))),
            crc: Default::default(),
            max_buffer_limit: limit,
        }
    }

    pub fn read_header(&mut self) -> Result<()> {
        let header = std::mem::replace(&mut self.current_part, Part::Temp);
        if let Part::Header(mut b) = header {
            let (typ, headers, _has_leading_data) =
                Self::read_header_internal(&mut b, self.max_buffer_limit)?;
            self.typ = Some(typ);
            self.headers = headers;
            self.current_part = Part::Body(Base64Decoder::new(Base64Reader::new(b)));
            return Ok(());
        }

        bail!("invalid state, cannot read header");
    }

    fn read_header_internal(b: &mut R, limit: usize) -> Result<(BlockType, Headers, bool)> {
        let (typ, headers, leading) = read_from_buf(b, "armor header", limit, header_parser)?;
        Ok((typ, headers, leading))
    }

    fn read_body(
        &mut self,
        into: &mut [u8],
        base_decoder: &mut Base64Decoder<Base64Reader<R>>,
    ) -> io::Result<usize> {
        let size = base_decoder.read(into)?;
        if let Some(mut crc) = self.crc {
            if size > 0 {
                crc.write(&into[0..size]);
            }
        }

        Ok(size)
    }

    fn read_footer(&mut self, mut b: BufReader<R>) -> Result<()> {
        let (checksum, footer_typ) =
            read_from_buf(&mut b, "armor footer", self.max_buffer_limit, footer_parser)?;
        if let Some(ref header_typ) = self.typ {
            if header_typ != &footer_typ {
                self.current_part = Part::Done(b);
                bail!(
                    "armor ascii footer does not match header: {:?} != {:?}",
                    self.typ,
                    footer_typ
                );
            }
        }
        self.checksum = checksum;
        self.current_part = Part::Done(b);

        if matches!(self.crc24_status(), ArmorCrc24Status::CheckedInvalid { .. }) {
            bail!("invalid crc24 checksum");
        }

        Ok(())
    }

    pub fn crc24_status(&self) -> ArmorCrc24Status {
        match (self.checksum, self.crc) {
            (None, _) => ArmorCrc24Status::NoCrc24,
            (Some(footer), None) => ArmorCrc24Status::Unchecked {
                footer_crc: footer as u32,
            },
            (Some(footer), Some(actual)) => {
                let calculated_crc = actual.finish();
                if footer == calculated_crc {
                    ArmorCrc24Status::CheckedOk { crc: footer as u32 }
                } else {
                    ArmorCrc24Status::CheckedInvalid {
                        footer_crc: footer as u32,
                        calculated_crc: calculated_crc as u32,
                    }
                }
            }
        }
    }
}

impl<R: BufRead> Read for Dearmor<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        loop {
            let current_part = std::mem::replace(&mut self.current_part, Part::Temp);
            match current_part {
                Part::Header(mut b) => {
                    let (typ, headers, _leading) =
                        Self::read_header_internal(&mut b, self.max_buffer_limit)
                            .map_err(io::Error::other)?;
                    self.typ = Some(typ);
                    self.headers = headers;
                    self.current_part = Part::Body(Base64Decoder::new(Base64Reader::new(b)));
                }
                Part::Body(mut b) => {
                    let last_read = self.read_body(&mut into[read..], &mut b)?;
                    if last_read == 0 && read < into.len() {
                        let (b, buf) = b.into_inner_with_buffer();
                        let b = BufReader::with_buffer(buf, b.into_inner());
                        self.current_part = Part::Footer(b);
                    } else {
                        self.current_part = Part::Body(b);
                    }
                    read += last_read;
                    if read == into.len() {
                        return Ok(read);
                    }
                }
                Part::Footer(mut b) => {
                    b.make_room();
                    while b.buf_len() < 128 {
                        let read = b.read_into_buf()?;
                        if read == 0 {
                            break;
                        }
                    }

                    self.read_footer(b).map_err(io::Error::other)?;
                }
                Part::Done(b) => {
                    self.current_part = Part::Done(b);
                    return Ok(read);
                }
                Part::Temp => panic!("invalid state"),
            }
        }
    }
}

pub(crate) fn read_from_buf<B: BufRead, T, P>(
    b: &mut B,
    ctx: &str,
    limit: usize,
    parser: P,
) -> Result<T>
where
    P: Fn(&[u8]) -> IResult<&[u8], T>,
{
    let buf = b.fill_buf()?;
    if buf.is_empty() {
        bail!("not enough bytes in buffer: {}", ctx);
    }
    match parser(buf) {
        Ok((remaining, res)) => {
            let consumed = buf.len() - remaining.len();
            b.consume(consumed);
            return Ok(res);
        }
        Err(nom::Err::Incomplete(_)) => {}
        Err(err) => {
            bail!("failed reading: {} {:?}", ctx, err);
        }
    };

    let mut back_buffer = buf.to_vec();
    let len = back_buffer.len();
    b.consume(len);

    let mut last_buffer_len;

    loop {
        if back_buffer.len() >= limit {
            bail!("input too large");
        }

        let buf = b.fill_buf()?;
        if buf.is_empty() {
            bail!("not enough bytes in buffer: {}", ctx);
        }
        last_buffer_len = buf.len();
        back_buffer.extend_from_slice(buf);

        match parser(&back_buffer) {
            Ok((remaining, res)) => {
                if remaining.len() > last_buffer_len {
                    bail!("inconsistent state: less data parsed than expected");
                }

                let consumed = last_buffer_len - remaining.len();
                b.consume(consumed);
                return Ok(res);
            }
            Err(nom::Err::Incomplete(_)) => {
                b.consume(last_buffer_len);
                continue;
            }
            Err(err) => {
                bail!("failed reading: {} {:?}", ctx, err);
            }
        };
    }
}
