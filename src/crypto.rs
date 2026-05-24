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

use crate::{error::SignerError, ui::Ui, BUFFER_SIZE};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use ring::digest;
use std::io::Read;

thread_local! { static STREAM_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0u8; BUFFER_SIZE]); }

pub struct CryptoEngine;

impl CryptoEngine {
    pub fn compute_sha1(data: &[u8]) -> String {
        base64_engine.encode(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref())
    }

    pub fn compute_sha1_with_ui(data: &[u8], ui: Option<&Ui>) -> String {
        if let Some(ui) = ui {
            if ui.debug {
                ui.debug(&format!("SHA1: {} bytes", data.len()));
            }
        }
        Self::compute_sha1(data)
    }

    pub fn compute_stream_sha1<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        Self::compute_stream_sha1_with_ui(reader, None, None)
    }

    pub fn compute_stream_sha1_with_ui<R: Read>(
        reader: &mut R,
        ui: Option<&Ui>,
        file_path: Option<&str>,
    ) -> Result<String, SignerError> {
        if let Some(ui) = ui {
            if let Some(path) = file_path {
                if ui.very_verbose || ui.verbose {
                    let msg = format!("SHA1: {}", path);
                    if ui.very_verbose {
                        ui.debug(&msg);
                    } else {
                        ui.info(&msg);
                    }
                }
            }
        }

        STREAM_BUF.with(|local_buf| {
            let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
            let mut buf = local_buf.borrow_mut();
            let mut processed = 0u64;
            loop {
                let count = reader.read(&mut buf)?;
                if count == 0 {
                    break;
                }
                ctx.update(&buf[..count]);
                processed += count as u64;

                if let Some(ui) = ui {
                    if ui.debug && processed % (BUFFER_SIZE as u64 * 10) == 0 {
                        ui.trace(&format!("SHA1: {} bytes", processed));
                    }
                }
            }

            if let Some(ui) = ui {
                if ui.very_verbose {
                    ui.debug(&format!("SHA1 complete: {} bytes", processed));
                }
            }

            Ok(base64_engine.encode(ctx.finish().as_ref()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_empty() {
        assert_eq!(
            CryptoEngine::compute_sha1(b""),
            "2jmj7l5rSw0yVb/vlWAYkK/YBwk="
        );
    }

    #[test]
    fn test_sha1_abc() {
        assert_eq!(
            CryptoEngine::compute_sha1(b"abc"),
            "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
        );
    }

    #[test]
    fn test_sha1_known() {
        let result = CryptoEngine::compute_sha1(b"hello");
        assert_eq!(result.len(), 28);
        assert!(result.ends_with("="));
    }

    #[test]
    fn test_stream_sha1() {
        let data = b"stream test data";
        let mut reader = std::io::Cursor::new(data);
        let result = CryptoEngine::compute_stream_sha1(&mut reader).unwrap();
        assert_eq!(result, CryptoEngine::compute_sha1(data));
    }

    #[test]
    fn test_stream_sha1_large() {
        let data = vec![0xABu8; 100000];
        let mut reader = std::io::Cursor::new(&data);
        let result = CryptoEngine::compute_stream_sha1(&mut reader).unwrap();
        assert_eq!(result, CryptoEngine::compute_sha1(&data));
    }
}
