// ZipSigner Rust - High-performance, memory-safe cryptographic signing and verification for Android ZIP archives
// Copyright (C) 2025 Tiash H Kabir / @MrCarb0n
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Error types and handling for the ZipSigner library.

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_display_io() {
        let e = SignerError::Io(io::Error::new(io::ErrorKind::NotFound, "no file"));
        let msg = format!("{}", e);
        assert!(msg.starts_with("I/O Error:"));
        assert!(msg.contains("no file"));
    }

    #[test]
    fn test_display_config() {
        let e = SignerError::Config("bad config".into());
        assert_eq!(format!("{}", e), "Configuration Error: bad config");
    }

    #[test]
    fn test_display_validation() {
        let e = SignerError::Validation("crc mismatch".into());
        assert_eq!(format!("{}", e), "Validation Error: crc mismatch");
    }

    #[test]
    fn test_from_io() {
        let inner = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let e: SignerError = inner.into();
        assert!(matches!(e, SignerError::Io(_)));
    }

    #[test]
    fn test_from_zip() {
        let inner = zip::result::ZipError::FileNotFound;
        let e: SignerError = inner.into();
        assert!(matches!(e, SignerError::Zip(_)));
    }

    #[test]
    fn test_error_impl() {
        let e = SignerError::Config("x".into());
        assert!(std::error::Error::source(&e).is_none());
    }
}
