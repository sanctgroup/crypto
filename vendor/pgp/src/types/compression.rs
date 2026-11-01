use num_enum::{FromPrimitive, IntoPrimitive};

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,

    Private10 = 110,

    #[num_enum(catch_all)]
    Other(u8),
}
