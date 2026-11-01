use std::io;

use generic_array::{
    typenum::{Sum, Unsigned, U2},
    ArrayLength, GenericArray,
};

const CRLF: [u8; 2] = *b"\r\n";
const CR: [u8; 1] = *b"\r";
const LF: [u8; 1] = *b"\n";

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LineBreak {
    Crlf,
    Lf,
    Cr,
}

impl AsRef<[u8]> for LineBreak {
    fn as_ref(&self) -> &[u8] {
        match self {
            LineBreak::Crlf => &CRLF[..],
            LineBreak::Lf => &LF[..],
            LineBreak::Cr => &CR[..],
        }
    }
}

pub struct LineWriter<'a, W, N>
where
    W: io::Write,
    N: Unsigned + ArrayLength<u8>,
    N: std::ops::Add<U2>,
    Sum<N, U2>: ArrayLength<u8>,
{
    line_break: LineBreak,
    w: &'a mut W,
    extra: GenericArray<u8, N>,
    extra_len: usize,
    buffer: GenericArray<u8, Sum<N, U2>>,
    finished: bool,
    panicked: bool,
}

impl<'a, W, N> LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArrayLength<u8>,
    N: std::ops::Add<U2>,
    Sum<N, U2>: ArrayLength<u8>,
{
    pub fn new(w: &'a mut W, line_break: LineBreak) -> Self {
        LineWriter {
            line_break,
            w,
            extra: Default::default(),
            buffer: Default::default(),
            extra_len: 0,
            finished: false,
            panicked: false,
        }
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        };

        if self.extra_len > 0 {
            self.panicked = true;
            self.w.write_all(&self.extra[..self.extra_len])?;
            self.w.write_all(self.line_break.as_ref())?;
            self.panicked = false;

            self.extra_len = 0;
        }

        self.finished = true;
        Ok(())
    }
}

impl<'a, W, N> io::Write for LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArrayLength<u8>,
    N: std::ops::Add<U2>,
    Sum<N, U2>: ArrayLength<u8>,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.finished {
            panic!("Cannot write more after calling finish()");
        }

        if input.is_empty() {
            return Ok(0);
        }

        let sl = N::to_usize();
        let line_break = self.line_break.as_ref();

        let orig_extra_len = self.extra_len;

        if self.extra_len + input.len() < sl {
            self.extra_len += input.len();
            self.extra[orig_extra_len..self.extra_len].copy_from_slice(input);
            Ok(input.len())
        } else {
            let mut buffer_pos = 0;
            let mut input_pos = 0;

            if self.extra_len > 0 {
                let copied = ::std::cmp::min(orig_extra_len, self.buffer.len());
                self.buffer[buffer_pos..buffer_pos + copied].copy_from_slice(&self.extra[..copied]);
                self.extra_len -= copied;
                buffer_pos += copied;
            }

            if buffer_pos < sl {
                let missing = ::std::cmp::min(sl - buffer_pos, input.len() - input_pos);

                self.buffer[buffer_pos..buffer_pos + missing]
                    .copy_from_slice(&input[input_pos..input_pos + missing]);

                buffer_pos += missing;
                input_pos += missing;
            }

            if buffer_pos < sl {
                return Ok(input_pos);
            }

            self.buffer[buffer_pos..buffer_pos + line_break.len()].copy_from_slice(line_break);
            buffer_pos += line_break.len();

            self.panicked = true;
            let r = self.w.write_all(&self.buffer[..buffer_pos]);
            self.panicked = false;

            match r {
                Ok(_) => Ok(input_pos),
                Err(err) => {
                    self.extra_len = orig_extra_len;
                    Err(err)
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl<'a, W, N> Drop for LineWriter<'a, W, N>
where
    W: 'a + io::Write,
    N: Unsigned + ArrayLength<u8>,
    N: std::ops::Add<U2>,
    Sum<N, U2>: ArrayLength<u8>,
{
    fn drop(&mut self) {
        if !self.panicked {
            let _ = self.finish();
        }
    }
}
