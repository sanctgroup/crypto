use std::{io, io::prelude::*};

#[derive(Debug)]
pub struct Base64Reader<R: BufRead> {
    inner: R,
}

impl<R: BufRead> Base64Reader<R> {
    pub fn new(input: R) -> Self {
        Base64Reader { inner: input }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: BufRead> Read for Base64Reader<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let mut buf = self.inner.fill_buf()?;
        if buf.is_empty() {
            return Ok(0);
        }

        let mut buf_i = 0;
        let mut n = 0;
        loop {
            while buf[buf_i] == b'\r' || buf[buf_i] == b'\n' {
                buf_i += 1;
                if buf_i == buf.len() {
                    break;
                }
            }

            if buf_i < buf.len() {
                if !is_base64_token(buf[buf_i]) {
                    break;
                }

                into[n] = buf[buf_i];
                n += 1;
                buf_i += 1;
                if n == into.len() {
                    break;
                }
            }

            if buf_i == buf.len() {
                self.inner.consume(buf_i);
                buf = self.inner.fill_buf()?;
                buf_i = 0;
                if buf.is_empty() {
                    break;
                }
            }
        }

        self.inner.consume(buf_i);

        Ok(n)
    }
}

#[inline]
fn is_base64_token(c: u8) -> bool {
    ((0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c))
        || (0x30..=0x39).contains(&c)
        || c == b'/'
        || c == b'+'
        || c == b'='
        || c == b'\n'
        || c == b'\r'
}
