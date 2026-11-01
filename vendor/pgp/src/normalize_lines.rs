use std::borrow::Cow;

use bytes::{Buf, BufMut, BytesMut};

use crate::{line_writer::LineBreak, util::fill_buffer};

pub struct NormalizedReader<R>
where
    R: std::io::Read,
{
    line_break: LineBreak,
    source: R,
    in_buffer: [u8; BUF_SIZE / 2],
    replaced: BytesMut,
    is_done: bool,
}

const BUF_SIZE: usize = 1024;
impl<R: std::io::Read> NormalizedReader<R> {
    pub fn new(source: R, line_break: LineBreak) -> Self {
        Self {
            source,
            line_break,
            in_buffer: [0u8; BUF_SIZE / 2],
            replaced: BytesMut::with_capacity(BUF_SIZE),
            is_done: false,
        }
    }

    fn fill_buffer(&mut self) -> std::io::Result<()> {
        let last_char = self.in_buffer[self.in_buffer.len() - 1];

        let read = fill_buffer(&mut self.source, &mut self.in_buffer, None)?;
        if read < self.in_buffer.len() {
            self.is_done = true;
        }

        self.cleanup_buffer(read, last_char);
        Ok(())
    }

    fn cleanup_buffer(&mut self, read: usize, last_char: u8) {
        const CR: u8 = b'\r';
        const LF: u8 = b'\n';

        self.replaced.clear();
        let mut start = 0;
        let mut end = read;

        if read == self.in_buffer.len() && self.in_buffer[self.in_buffer.len() - 1] == CR {
            end = read - 1;
        }

        let edge_case = [last_char, self.in_buffer[0]];
        match (edge_case, read > 0) {
            ([CR, LF], true) => {
                let res = replace_newlines(&edge_case, self.line_break.as_ref());
                self.replaced.extend_from_slice(&res);

                start = 1;
            }
            ([CR, _], _) => {
                self.replaced.put_u8(CR);
            }
            _ => {}
        }

        let res = replace_newlines(&self.in_buffer[start..end], self.line_break.as_ref());

        self.replaced.extend_from_slice(&res);
    }
}

impl<R: std::io::Read> std::io::Read for NormalizedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.replaced.has_remaining() {
            if self.is_done {
                return Ok(0);
            }
            self.fill_buffer()?;
        }

        let to_write = self.replaced.remaining().min(buf.len());
        self.replaced.copy_to_slice(&mut buf[..to_write]);
        Ok(to_write)
    }
}

pub(crate) fn normalize_lines(s: &str, line_break: LineBreak) -> Cow<'_, str> {
    let bytes = replace_newlines(s.as_bytes(), line_break.as_ref());
    match bytes {
        Cow::Borrowed(bytes) => Cow::Borrowed(std::str::from_utf8(bytes).expect("valid bytes in")),
        Cow::Owned(bytes) => {
            Cow::Owned(std::string::String::from_utf8(bytes).expect("valid bytes in"))
        }
    }
}

fn replace_newlines<'a>(input: &'a [u8], replacement: &[u8]) -> Cow<'a, [u8]> {
    let mut newlines = memchr::memchr_iter(b'\n', input).peekable();
    if newlines.peek().is_none() {
        return Cow::Borrowed(input);
    }

    let mut out = Vec::with_capacity(input.len());
    let mut position = 0;

    for newline in newlines {
        let start = if newline > 0 && input[newline - 1] == b'\r' {
            newline - 1
        } else {
            newline
        };

        out.extend_from_slice(&input[position..start]);
        out.extend_from_slice(replacement);
        position = newline + 1;
    }

    out.extend_from_slice(&input[position..]);
    Cow::Owned(out)
}
