use std::array::TryFromSliceError;
use std::fmt::Debug;
use std::io;

use simpletcp::simpletcp::MessageError;

use crate::error::Error::{CorruptedMessage, IOError, NetworkError};

#[derive(Debug)]
pub enum Error {
    NetworkError(simpletcp::simpletcp::Error),
    IOError(io::Error),
    HashCollision,
    CorruptedStorage,
    CorruptedMessage,
}

impl From<simpletcp::simpletcp::Error> for Error {
    fn from(e: simpletcp::simpletcp::Error) -> Self {
        NetworkError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        IOError(e)
    }
}

impl From<MessageError> for Error {
    fn from(_: MessageError) -> Self {
        CorruptedMessage
    }
}

impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Self {
        CorruptedMessage
    }
}
