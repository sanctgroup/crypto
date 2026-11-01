use generic_array::{
    typenum::{U16, U24, U32},
    GenericArray,
};
use snafu::{ResultExt, Snafu};
use zeroize::Zeroizing;

const IV_LEN: usize = 8;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid key size: {}", size))]
    InvalidKeySize { size: usize },
    #[snafu(display("invalid data size: {}", size))]
    InvalidDataSize { size: usize },
    #[snafu(display("wrap failed"))]
    Wrap { source: aes_kw::Error },
    #[snafu(display("unwrap failed"))]
    Unwrap { source: aes_kw::Error },
}

pub fn wrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let aes_size = key.len() * 8;
    let res = match aes_size {
        128 => {
            let key = GenericArray::<u8, U16>::from_slice(key);
            let kek = aes_kw::KekAes128::new(key);
            kek.wrap_vec(data)
        }
        192 => {
            let key = GenericArray::<u8, U24>::from_slice(key);
            let kek = aes_kw::KekAes192::new(key);
            kek.wrap_vec(data)
        }
        256 => {
            let key = GenericArray::<u8, U32>::from_slice(key);
            let kek = aes_kw::KekAes256::new(key);
            kek.wrap_vec(data)
        }
        _ => {
            return Err(InvalidKeySizeSnafu { size: aes_size }.build());
        }
    };
    res.context(WrapSnafu)
}

pub fn unwrap(key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let out_len = data
        .len()
        .checked_sub(IV_LEN)
        .ok_or(Error::InvalidDataSize { size: data.len() })?;

    let mut out = Zeroizing::new(vec![0u8; out_len]);

    let aes_size = key.len() * 8;
    match aes_size {
        128 => {
            let key = GenericArray::<u8, U16>::from_slice(key);
            let kek = aes_kw::KekAes128::new(key);
            kek.unwrap(data, &mut out)
        }
        192 => {
            let key = GenericArray::<u8, U24>::from_slice(key);
            let kek = aes_kw::KekAes192::new(key);
            kek.unwrap(data, &mut out)
        }
        256 => {
            let key = GenericArray::<u8, U32>::from_slice(key);
            let kek = aes_kw::KekAes256::new(key);
            kek.unwrap(data, &mut out)
        }
        _ => {
            return Err(InvalidKeySizeSnafu { size: aes_size }.build());
        }
    }
    .context(WrapSnafu)?;

    Ok(out)
}
