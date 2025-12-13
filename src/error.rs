/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

//! Error types and handling for the ZipSigner library.
//! Defines all possible errors that can occur during ZIP signing operations.

use std::{fmt, io};

/// Comprehensive error type for all signing operations.
#[derive(Debug)]
pub enum SignerError {
    /// I/O errors during file operations
    Io(io::Error),
    /// ZIP format errors during archive processing
    Zip(zip::result::ZipError),
    /// Cryptographic operation errors
    Ring(ring::error::Unspecified),
    /// PEM format parsing errors
    Pem(pem::PemError),
    /// Validation failures during signature checking
    Validation(String),
    /// Configuration or setup errors
    Config(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::Io(e) => write!(f, "I/O Error: {}", e),
            SignerError::Zip(e) => write!(f, "ZIP Error: {}", e),
            SignerError::Ring(e) => write!(f, "Cryptography Error: {}", e),
            SignerError::Pem(e) => write!(f, "PEM Parsing Error: {}", e),
            SignerError::Validation(s) => write!(f, "Validation Error: {}", s),
            SignerError::Config(s) => write!(f, "Configuration Error: {}", s),
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
