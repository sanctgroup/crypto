use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::{
    errors::{ensure, Result},
    line_writer::LineBreak,
    normalize_lines::normalize_lines,
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{PacketHeaderVersion, PacketLength, Tag, Timestamp},
    util::fill_buffer,
};

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]

pub struct LiteralData {
    packet_header: PacketHeader,
    header: LiteralDataHeader,
    #[debug("{}", hex::encode(data))]
    #[cfg_attr(
        test,
        proptest(
            strategy = "any::<Vec<u8>>().prop_map(Into::into)",
            filter = "|d| !d.is_empty()"
        )
    )]
    data: Bytes,
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct LiteralDataHeader {
    mode: DataMode,
    file_name: Bytes,
    created: Timestamp,
}

impl LiteralDataHeader {
    pub fn new(mode: DataMode) -> Self {
        Self {
            mode,
            file_name: "".into(),
            created: Timestamp::default(),
        }
    }

    pub fn mode(&self) -> DataMode {
        self.mode
    }

    pub fn file_name(&self) -> &Bytes {
        &self.file_name
    }

    pub fn created(&self) -> Timestamp {
        self.created
    }
}

impl LiteralDataHeader {
    pub fn try_from_reader<R: BufRead>(mut r: R) -> io::Result<Self> {
        let mode = r.read_u8().map(DataMode::from)?;

        let name_len = r.read_u8()?;
        let file_name = r.take_bytes(name_len.into())?;

        let created = r.read_timestamp()?;

        Ok(Self {
            mode,
            file_name: file_name.freeze(),
            created,
        })
    }
}

#[derive(Debug, Copy, Clone, FromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u8)]

pub enum DataMode {
    Binary = b'b',
    Text = b't',
    Utf8 = b'u',
    Mime = b'm',

    #[num_enum(catch_all)]
    Other(u8),
}

impl LiteralData {
    pub fn from_str(file_name: impl Into<Bytes>, raw_data: &str) -> Result<Self> {
        let data: Bytes = normalize_lines(raw_data, LineBreak::Crlf)
            .to_string()
            .into();
        let header = LiteralDataHeader {
            mode: DataMode::Utf8,
            file_name: file_name.into(),
            created: Timestamp::now(),
        };
        let len = header.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len.try_into()?);

        Ok(LiteralData {
            packet_header,
            header,
            data,
        })
    }

    pub fn from_bytes(file_name: impl Into<Bytes>, data: Bytes) -> Result<Self> {
        let header = LiteralDataHeader {
            mode: DataMode::Binary,
            file_name: file_name.into(),
            created: Timestamp::now(),
        };
        let len = header.write_len() + data.len();
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len.try_into()?);

        Ok(LiteralData {
            packet_header,
            header,
            data,
        })
    }

    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        let header = LiteralDataHeader::try_from_reader(&mut data)?;
        let data = data.rest()?;

        Ok(LiteralData {
            packet_header,
            header,
            data: data.freeze(),
        })
    }

    pub fn file_name(&self) -> &Bytes {
        &self.header.file_name
    }

    pub fn is_binary(&self) -> bool {
        matches!(self.header.mode, DataMode::Binary)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    #[inline]
    pub fn try_into_string(self) -> Result<String, Bytes> {
        let Self { data, .. } = self;
        match self.header.mode {
            DataMode::Binary => Err(data),
            _ => match std::string::String::from_utf8(Vec::from(data)) {
                Ok(data) => Ok(data),
                Err(error) => Err(error.into_bytes().into()),
            },
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self.header.mode {
            DataMode::Binary => None,
            _ => std::str::from_utf8(&self.data).ok(),
        }
    }
}

impl AsRef<[u8]> for LiteralData {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for LiteralDataHeader {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let name = &self.file_name;
        writer.write_u8(self.mode.into())?;
        writer.write_u8(name.len().try_into()?)?;
        writer.write_all(name)?;
        self.created.to_writer(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1 + 1;
        sum += self.file_name.len();
        sum += self.created.write_len();
        sum
    }
}

impl Serialize for LiteralData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.header.to_writer(writer)?;

        writer.write_all(&self.data)?;

        Ok(())
    }
    fn write_len(&self) -> usize {
        let mut sum = self.header.write_len();
        sum += self.data.len();
        sum
    }
}

impl PacketTrait for LiteralData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

pub(crate) enum LiteralCheckingReader<R: io::Read> {
    Utf8Checking(CrLfCheckReader<Utf8CheckReader<R>>),
    BinaryRaw(R),
}

impl<R: io::Read> LiteralCheckingReader<R> {
    pub(crate) fn into_inner(self) -> R {
        match self {
            Self::Utf8Checking(s) => s.into_inner().into_inner(),
            Self::BinaryRaw(s) => s,
        }
    }
}

impl<R: io::Read> io::Read for LiteralCheckingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Utf8Checking(r) => r.read(buf),
            Self::BinaryRaw(r) => r.read(buf),
        }
    }
}

pub(crate) struct CrLfCheckReader<R>
where
    R: io::Read,
{
    source: R,
    last_was_cr: bool,
}

impl<R: io::Read> CrLfCheckReader<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            last_was_cr: false,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: io::Read> io::Read for CrLfCheckReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.source.read(buf)?;

        if len == 0 {
            return Ok(0);
        }

        let mut pos = if self.last_was_cr && buf[0] == b'\n' {
            1
        } else {
            0
        };

        while pos < len - 1 {
            if buf[pos] == b'\n' {
                return Err(io::Error::other(
                    "Illegal line ending (LF without preceding CR)",
                ));
            }

            if buf[pos] == b'\r' && buf[pos + 1] == b'\n' {
                pos += 2;
            } else {
                pos += 1;
            }
        }

        if pos < len && buf[pos] == b'\n' {
            return Err(io::Error::other(
                "Illegal line ending (LF without preceding CR)",
            ));
        }

        self.last_was_cr = buf[len - 1] == b'\r';

        Ok(len)
    }
}

pub(crate) struct Utf8CheckReader<R>
where
    R: io::Read,
{
    source: R,

    rest: Option<Vec<u8>>,
}

impl<R: io::Read> Utf8CheckReader<R> {
    fn new(source: R) -> Self {
        Self { source, rest: None }
    }

    pub(crate) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: io::Read> io::Read for Utf8CheckReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        fn check_utf8(data: &[u8]) -> Result<Option<Vec<u8>>, io::Error> {
            match std::str::from_utf8(data) {
                Ok(_) => Ok(None),
                Err(err) => {
                    let valid_up_to = err.valid_up_to();

                    let rest = &data[valid_up_to..];

                    match rest.len() {
                        0 => Ok(None),
                        1..=3 => Ok(Some(Vec::from(rest))),

                        4.. => Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid UTF-8 data",
                        )),
                    }
                }
            }
        }

        let len = self.source.read(buf)?;

        if len == 0 {
            if self.rest.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid UTF-8 data",
                ));
            }

            return Ok(0);
        }

        self.rest = if let Some(mut check) = self.rest.take() {
            check.extend_from_slice(&buf[..len]);
            check_utf8(&check)?
        } else {
            check_utf8(&buf[..len])?
        };

        Ok(len)
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum LiteralDataGenerator<R: io::Read> {
    Fixed(LiteralDataFixedGenerator<LiteralCheckingReader<R>>),
    Partial(LiteralDataPartialGenerator<LiteralCheckingReader<R>>),
}

impl<R: io::Read> LiteralDataGenerator<R> {
    pub(crate) fn new(
        header: LiteralDataHeader,
        source: R,
        source_len: Option<u32>,
        chunk_size: u32,
    ) -> Result<Self> {
        let source = if header.mode == DataMode::Utf8 {
            let utf8 = Utf8CheckReader::new(source);
            let crlf = CrLfCheckReader::new(utf8);

            LiteralCheckingReader::Utf8Checking(crlf)
        } else {
            LiteralCheckingReader::BinaryRaw(source)
        };

        Self::from_normalized(header, source, source_len, chunk_size)
    }

    pub(crate) fn from_normalized(
        header: LiteralDataHeader,
        source: LiteralCheckingReader<R>,
        source_len: Option<u32>,
        chunk_size: u32,
    ) -> Result<Self> {
        match source_len {
            Some(source_len) => {
                let genn = LiteralDataFixedGenerator::new(header, source, source_len)?;
                Ok(Self::Fixed(genn))
            }
            None => {
                let genn = LiteralDataPartialGenerator::new(header, source, chunk_size)?;
                Ok(Self::Partial(genn))
            }
        }
    }

    pub(crate) fn len(&self) -> Option<u32> {
        match self {
            Self::Fixed(ref fixed) => Some(fixed.total_len),
            Self::Partial { .. } => None,
        }
    }

    pub(crate) fn into_inner(self) -> R {
        match self {
            Self::Fixed(s) => s.into_inner().into_inner(),
            Self::Partial(s) => s.into_inner().into_inner(),
        }
    }
}

impl<R: io::Read> io::Read for LiteralDataGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = match self {
            Self::Fixed(ref mut fixed) => fixed.read(buf)?,
            Self::Partial(ref mut partial) => partial.read(buf)?,
        };
        Ok(read)
    }
}

pub(crate) struct LiteralDataFixedGenerator<R: io::Read> {
    header: Vec<u8>,
    source: R,
    header_written: usize,
    total_len: u32,
}

impl<R: io::Read> LiteralDataFixedGenerator<R> {
    pub(crate) fn new(header: LiteralDataHeader, source: R, source_len: u32) -> Result<Self> {
        let len = source_len + u32::try_from(header.write_len())?;
        let packet_header = PacketHeader::new_fixed(Tag::LiteralData, len);
        let mut serialized_header = Vec::new();
        packet_header.to_writer(&mut serialized_header)?;
        header.to_writer(&mut serialized_header)?;

        let total_len = source_len + u32::try_from(serialized_header.len())?;

        Ok(Self {
            header: serialized_header,
            source,
            header_written: 0,
            total_len,
        })
    }

    pub(crate) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: io::Read> io::Read for LiteralDataFixedGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let header_bytes_left = self.header.len() - self.header_written;
        if header_bytes_left > 0 {
            let to_write = header_bytes_left.min(buf.len());
            buf[..to_write]
                .copy_from_slice(&self.header[self.header_written..self.header_written + to_write]);
            self.header_written += to_write;
            Ok(to_write)
        } else {
            self.source.read(buf)
        }
    }
}

pub(crate) struct LiteralDataPartialGenerator<R: io::Read> {
    header: LiteralDataHeader,
    source: R,
    buffer: Box<[u8]>,
    chunk_size: u32,
    is_done: bool,
    is_first: bool,
    is_fixed_emitted: bool,
    current_packet: BytesMut,
}

impl<R: io::Read> LiteralDataPartialGenerator<R> {
    pub(crate) fn new(header: LiteralDataHeader, source: R, chunk_size: u32) -> Result<Self> {
        ensure!(chunk_size >= 512, "chunk size must be larger than 512");
        ensure!(
            chunk_size.is_power_of_two(),
            "chunk size must be a power of two"
        );
        Ok(Self {
            header,
            source,
            buffer: vec![0u8; chunk_size as usize].into_boxed_slice(),
            chunk_size,
            is_done: false,
            is_first: true,
            is_fixed_emitted: false,
            current_packet: BytesMut::with_capacity(chunk_size as usize),
        })
    }

    pub(crate) fn into_inner(self) -> R {
        self.source
    }
}

impl<R: io::Read> io::Read for LiteralDataPartialGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.current_packet.has_remaining() {
            if self.is_done && self.is_fixed_emitted {
                return Ok(0);
            }

            let chunk_size = if self.is_first {
                self.chunk_size as usize - self.header.write_len()
            } else {
                self.chunk_size as usize
            };

            let buf_size = match fill_buffer(&mut self.source, &mut self.buffer, Some(chunk_size)) {
                Ok(size) => size,
                Err(err) => {
                    self.is_done = true;
                    return Err(err);
                }
            };

            debug!("read chunk {buf_size} bytes");
            debug_assert!(buf_size <= u32::MAX as usize);

            if buf_size == 0 && self.is_fixed_emitted {
                self.is_done = true;
                return Ok(0);
            }

            let data = &self.buffer[..buf_size];

            let packet_length = if self.is_first && buf_size < chunk_size {
                self.is_done = true;
                self.is_fixed_emitted = true;
                let len = (buf_size + self.header.write_len())
                    .try_into()
                    .map_err(|_| io::Error::other("too large"))?;
                PacketLength::Fixed(len)
            } else if buf_size == chunk_size {
                PacketLength::Partial(self.chunk_size)
            } else {
                self.is_done = true;
                self.is_fixed_emitted = true;
                let len = data
                    .len()
                    .try_into()
                    .map_err(|_| io::Error::other("too large"))?;
                PacketLength::Fixed(len)
            };

            let mut writer = std::mem::take(&mut self.current_packet).writer();
            if self.is_first {
                let packet_header = PacketHeader::from_parts(
                    PacketHeaderVersion::New,
                    Tag::LiteralData,
                    packet_length,
                )
                .expect("known construction");
                packet_header
                    .to_writer(&mut writer)
                    .map_err(io::Error::other)?;

                self.header
                    .to_writer(&mut writer)
                    .map_err(io::Error::other)?;

                debug!("first partial packet {packet_header:?}");
                self.is_first = false;
            } else {
                packet_length
                    .to_writer_new(&mut writer)
                    .map_err(io::Error::other)?;
                debug!("partial packet {packet_length:?}");
            };

            let mut packet_ser = writer.into_inner();
            packet_ser.extend_from_slice(data);
            self.current_packet = packet_ser;
        }

        let to_write = self.current_packet.remaining().min(buf.len());
        self.current_packet.copy_to_slice(&mut buf[..to_write]);
        Ok(to_write)
    }
}
