/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

//! Cryptographic operations for ZIP signing.
//! Provides SHA1 hash computation for data and streams.

use crate::{error::SignerError, BUFFER_SIZE};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use ring::digest;
use std::io::Read;

/// Core cryptographic engine for computing hashes needed for ZIP signing.
pub struct CryptoEngine;

impl CryptoEngine {
    /// Calculate SHA1 hash for the provided data and return as base64-encoded string.
    ///
    /// # Arguments
    /// * `data` - The byte slice to hash
    ///
    /// # Returns
    /// Base64-encoded SHA1 hash of the input data
    pub fn compute_sha1(data: &[u8]) -> String {
        let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
        base64_engine.encode(digest.as_ref())
    }

    /// Calculate SHA1 hash while reading from a stream to avoid loading full data into memory.
    ///
    /// # Arguments
    /// * `reader` - A mutable reference to a Read implementation
    ///
    /// # Returns
    /// Result containing the base64-encoded SHA1 hash or a SignerError
    ///
    /// # Errors
    /// Returns SignerError if there's an issue reading from the stream
    pub fn compute_stream_sha1<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);

        // Use thread-local buffer to avoid allocations
        thread_local! {
            static PROCESSING_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0u8; BUFFER_SIZE]);
        }

        PROCESSING_BUFFER.with(|buf| {
            let mut buffer = buf.borrow_mut();
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                context.update(&buffer[..count]);
            }
            let digest = context.finish();
            Ok(base64_engine.encode(digest.as_ref()))
        })
    }
}
