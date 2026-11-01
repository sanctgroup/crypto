use std::{hash::Hasher, io::Write};

use base64::engine::{general_purpose, Engine as _};
use crc24::Crc24Hasher;
use generic_array::typenum::U64;

use super::Headers;
use crate::{
    armor::BlockType,
    errors::Result,
    line_writer::{LineBreak, LineWriter},
    ser::Serialize,
    util::TeeWriter,
};

pub fn write(
    source: &impl Serialize,
    typ: BlockType,
    writer: &mut impl Write,
    headers: Option<&Headers>,
    include_checksum: bool,
) -> Result<()> {
    write_header(writer, typ, headers)?;

    let mut crc_hasher = include_checksum.then(Crc24Hasher::new);

    write_body(writer, source, crc_hasher.as_mut())?;

    write_footer(writer, typ, crc_hasher)?;

    Ok(())
}

pub(crate) fn write_header(
    writer: &mut impl Write,
    typ: BlockType,
    headers: Option<&Headers>,
) -> Result<()> {
    writer.write_all(&b"-----BEGIN "[..])?;
    typ.to_writer(writer)?;
    writer.write_all(&b"-----\n"[..])?;

    if let Some(headers) = headers {
        for (key, values) in headers.iter() {
            for value in values {
                writer.write_all(key.as_bytes())?;
                writer.write_all(&b": "[..])?;
                writer.write_all(value.as_bytes())?;
                writer.write_all(&b"\n"[..])?;
            }
        }
    }

    writer.write_all(&b"\n"[..])?;
    writer.flush()?;

    Ok(())
}

fn write_body(
    writer: &mut impl Write,
    source: &impl Serialize,
    crc_hasher: Option<&mut Crc24Hasher>,
) -> Result<()> {
    {
        let mut line_wrapper = LineWriter::<_, U64>::new(writer.by_ref(), LineBreak::Lf);
        let mut enc = Base64Encoder::new(&mut line_wrapper);

        if let Some(crc_hasher) = crc_hasher {
            let mut tee = TeeWriter::new(crc_hasher, &mut enc);
            source.to_writer(&mut tee)?;
        } else {
            source.to_writer(&mut enc)?;
        }
    }

    Ok(())
}

pub(crate) fn write_footer(
    writer: &mut impl Write,
    typ: BlockType,
    crc_hasher: Option<Crc24Hasher>,
) -> Result<()> {
    if let Some(crc_hasher) = crc_hasher {
        writer.write_all(b"=")?;

        let crc = crc_hasher.finish() as u32;
        let crc_buf = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
        let crc_enc = general_purpose::STANDARD.encode(crc_buf);

        writer.write_all(crc_enc.as_bytes())?;
        writer.write_all(&b"\n"[..])?;
    }

    writer.write_all(&b"-----END "[..])?;
    typ.to_writer(writer)?;
    writer.write_all(&b"-----\n"[..])?;
    Ok(())
}

pub(crate) struct Base64Encoder<W: std::io::Write>(
    base64::write::EncoderWriter<'static, general_purpose::GeneralPurpose, W>,
);

impl<W: std::io::Write> Base64Encoder<W> {
    pub(crate) fn new(writer: W) -> Self {
        Self(base64::write::EncoderWriter::new(
            writer,
            &general_purpose::STANDARD,
        ))
    }
}
impl<W: std::io::Write> std::io::Write for Base64Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            match self.0.write(buf) {
                Ok(0) => {}
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
