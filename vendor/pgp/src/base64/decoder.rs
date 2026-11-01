use std::io::{self, BufRead, Read};

use base64::engine::{general_purpose::GeneralPurpose, Engine};
use buffer_redux::{BufReader, Buffer};

const BUF_SIZE: usize = 1024;
const BUF_CAPACITY: usize = BUF_SIZE / 4 * 3;
const ENGINE: GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug)]
pub struct Base64Decoder<R> {
    inner: BufReader<R>,
    out: Buffer,
    out_buffer: [u8; BUF_CAPACITY],
    err: Option<io::Error>,
}

impl<R: Read> Base64Decoder<R> {
    pub fn new(input: R) -> Self {
        Base64Decoder {
            inner: BufReader::with_capacity(BUF_SIZE, input),
            out: Buffer::with_capacity(BUF_CAPACITY),
            out_buffer: [0u8; BUF_CAPACITY],
            err: None,
        }
    }

    pub fn into_inner_with_buffer(self) -> (R, Buffer) {
        self.inner.into_inner_with_buffer()
    }
}

impl<R: Read> Read for Base64Decoder<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        if !self.out.is_empty() {
            let len = self.out.copy_to_slice(into);
            return Ok(len);
        }

        if let Some(ref err) = self.err {
            return Err(copy_err(err));
        }

        if self.inner.buf_len() < 4 {
            let b = &mut self.inner;

            if let Err(err) = b.read_into_buf() {
                self.err = Some(copy_err(&err));
                return Err(err);
            }
        }

        if self.inner.buf_len() == 0 {
            return Ok(0);
        }

        let nr = self.inner.buf_len() / 4 * 4;
        let nw = self.inner.buf_len() / 4 * 3;

        let (consumed, written) = if nw > into.len() {
            let (consumed, nw) =
                try_decode_engine_slice(&self.inner.buffer()[..nr], &mut self.out_buffer[..]);

            let n = std::cmp::min(nw, into.len());
            let t = &self.out_buffer[0..nw];
            let (t1, t2) = t.split_at(n);

            into[0..n].copy_from_slice(t1);

            self.out.copy_from_slice(t2);

            (consumed, n)
        } else {
            try_decode_engine_slice(&self.inner.buffer()[..nr], into)
        };

        self.inner.consume(consumed);

        Ok(written)
    }
}

fn try_decode_engine_slice<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    output: &mut [u8],
) -> (usize, usize) {
    let input_bytes = input.as_ref();
    let mut n = input_bytes.len();
    while n > 0 {
        match ENGINE.decode_slice(&input_bytes[..n], output) {
            Ok(size) => {
                return (n, size);
            }
            Err(_) => {
                if n % 4 != 0 {
                    n -= n % 4
                } else {
                    n -= 4
                }
            }
        }
    }

    (0, 0)
}

fn copy_err(err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), err.to_string())
}
