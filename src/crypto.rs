/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::{error::SignerError, BUFFER_SIZE};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use ring::digest;
use std::io::Read;

pub struct CryptoEngine;

impl CryptoEngine {
    pub fn compute_sha1(data: &[u8]) -> String {
        let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
        base64_engine.encode(digest.as_ref())
    }

    pub fn compute_stream_sha1<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);

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
