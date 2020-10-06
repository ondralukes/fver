use crate::error::Error::{EncodingError, OpenSSLError};
use std::fmt::{Debug, Formatter};
use std::string::FromUtf8Error;
use std::{fmt, io};

pub enum Error {
    IOError(io::Error),
    NoDataDirectory,
    OpenSSLError(openssl::error::ErrorStack),
    EncodingError(FromUtf8Error),
    HashCollision,
    IllegalState,
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::IOError(e) => f.write_fmt(format_args!("IOError: {}", e)),
            Error::NoDataDirectory => f.write_str("NoDataDirectory"),
            OpenSSLError(e) => f.write_fmt(format_args!("OpenSSLError: {}", e)),
            EncodingError(e) => f.write_fmt(format_args!("EncodingError: {}", e)),
            Error::HashCollision => f.write_str("HashCollision"),
            Error::IllegalState => f.write_str("IllegalState"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        OpenSSLError(err)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        EncodingError(err)
    }
}
