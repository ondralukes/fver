use crate::error::Error::{CorruptedMessage, EncodingError, IOError, NetworkError, OpenSSLError};
use simpletcp;
use simpletcp::simpletcp::MessageError;
use std::array::TryFromSliceError;
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::string::FromUtf8Error;
use std::{fmt, io};

pub enum Error {
    NetworkError(simpletcp::simpletcp::Error),
    CorruptedMessage,
    OpenSSLError(openssl::error::ErrorStack),
    IOError(io::Error),
    EncodingError(FromUtf8Error),
    ServerError,
    NoDataDirectory,
}

impl From<simpletcp::simpletcp::Error> for Error {
    fn from(e: simpletcp::simpletcp::Error) -> Self {
        NetworkError(e)
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

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        IOError(e)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        OpenSSLError(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        EncodingError(e)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError(e) => f.write_fmt(format_args!("NetworkError: {:?}", e)),
            CorruptedMessage => f.write_str("CorruptedMessage"),
            OpenSSLError(e) => f.write_fmt(format_args!("OpenSSLError: {:?}", e)),
            IOError(e) => f.write_fmt(format_args!("IOError: {:?}", e)),
            EncodingError(e) => f.write_fmt(format_args!("EncodingError: {:?}", e)),
            Error::ServerError => f.write_str("ServerError"),
            Error::NoDataDirectory => f.write_str("NoDataDirectory"),
        }
    }
}
