use std::array::TryFromSliceError;
use std::fmt::Debug;
use std::io;

use simpletcp::simpletcp::MessageError;

use crate::error::Error::{CorruptedMessage, IOError, NetworkError, OpenSSLError};
use openssl::error::ErrorStack;
use std::convert::Infallible;

#[derive(Debug)]
pub enum Error {
    NetworkError(simpletcp::simpletcp::Error),
    OpenSSLError(openssl::error::ErrorStack),
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

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        CorruptedMessage
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        OpenSSLError(e)
    }
}
