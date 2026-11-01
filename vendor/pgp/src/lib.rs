#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![allow(clippy::missing_const_for_fn, clippy::type_complexity)]
#![deny(unsafe_code)]

pub use bytes;

pub(crate) mod util;

pub mod adapter;
pub mod armor;
pub mod base64;
pub mod composed;
pub mod crypto;
pub mod errors;
pub mod line_writer;
pub mod normalize_lines;
pub mod packet;
pub mod ser;
pub mod types;

mod parsing;
mod parsing_reader;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
