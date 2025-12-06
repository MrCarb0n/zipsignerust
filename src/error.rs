/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2024 Tiash / @MrCarb0n and Earth Inc.
 * Licensed under the MIT License.
 */

use std::{fmt, io};

#[derive(Debug)]
pub enum SignerError {
    Io(io::Error),
    Zip(zip::result::ZipError),
    Ring(ring::error::Unspecified),
    Pem(pem::PemError),
    Validation(String),
    Config(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::Io(e) => write!(f, "I/O Error: {}", e),
            SignerError::Zip(e) => write!(f, "ZIP Error: {}", e),
            SignerError::Ring(e) => write!(f, "Cryptography Error: {:?}", e),
            SignerError::Pem(e) => write!(f, "PEM Parsing Error: {}", e),
            SignerError::Validation(s) => write!(f, "Validation Failed: {}", s),
            SignerError::Config(s) => write!(f, "Config Error: {}", s),
        }
    }
}

impl std::error::Error for SignerError {}

impl From<io::Error> for SignerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<zip::result::ZipError> for SignerError {
    fn from(e: zip::result::ZipError) -> Self {
        Self::Zip(e)
    }
}

impl From<ring::error::Unspecified> for SignerError {
    fn from(e: ring::error::Unspecified) -> Self {
        Self::Ring(e)
    }
}

impl From<pem::PemError> for SignerError {
    fn from(e: pem::PemError) -> Self {
        Self::Pem(e)
    }
}
