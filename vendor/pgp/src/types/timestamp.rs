use std::fmt;
#[cfg(not(feature = "wasm"))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use byteorder::BigEndian;
#[cfg(feature = "wasm")]
use web_time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ser::Serialize;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Timestamp(u32);

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let time: SystemTime = (*self).into();
        write!(f, "Timestamp({:?})", time)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(value: Timestamp) -> Self {
        UNIX_EPOCH + Duration::from_secs(u64::from(value.0))
    }
}

impl TryFrom<SystemTime> for Timestamp {
    type Error = TimestampError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        let duration = value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TooFarBackSnafu.build())?;
        let val: u32 = duration
            .as_secs()
            .try_into()
            .map_err(|_| TooFarIntoTheFutureSnafu.build())?;
        Ok(Self(val))
    }
}

#[derive(Debug, snafu::Snafu)]
pub enum TimestampError {
    #[snafu(display("time was before 1970-01-01 00:00:00"))]
    TooFarBack,
    #[snafu(display("time is more than u32::MAX seconds into the future"))]
    TooFarIntoTheFuture,
}

impl Timestamp {
    pub fn now() -> Self {
        SystemTime::now()
            .try_into()
            .expect("now is too far into the future")
    }

    pub fn as_secs(self) -> u32 {
        self.0
    }

    pub fn from_secs(secs: u32) -> Self {
        Self(secs)
    }
}

impl Serialize for Timestamp {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        use byteorder::WriteBytesExt;
        writer.write_u32::<BigEndian>(self.0)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        4
    }
}
