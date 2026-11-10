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

pub struct CryptoEngine;

impl CryptoEngine {
    /// Base64 one-shot digest of `data` under any algorithm.
    pub fn compute_digest(alg: &'static digest::Algorithm, data: &[u8]) -> String {
        base64_engine.encode(digest::digest(alg, data).as_ref())
    }

    pub fn compute_sha1(data: &[u8]) -> String {
        Self::compute_digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data)
    }

    pub fn compute_sha256(data: &[u8]) -> String {
        Self::compute_digest(&digest::SHA256, data)
    }

    pub fn compute_stream_sha1<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        Self::compute_stream_digest(reader, &digest::SHA1_FOR_LEGACY_USE_ONLY, None, None)
    }

    pub fn compute_stream_sha256<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        Self::compute_stream_digest(reader, &digest::SHA256, None, None)
    }

    pub fn compute_stream_sha256_with_ui<R: Read>(
        reader: &mut R,
        ui: Option<&Ui>,
        file_path: Option<&str>,
    ) -> Result<String, SignerError> {
        Self::compute_stream_digest(reader, &digest::SHA256, ui, file_path)
    }

    pub(crate) fn compute_stream_digest<R: Read>(
        reader: &mut R,
        alg: &'static digest::Algorithm,
        ui: Option<&Ui>,
        file_path: Option<&str>,
    ) -> Result<String, SignerError> {
        if let (Some(ui), Some(path)) = (ui, file_path) {
            if ui.very_verbose || ui.verbose {
                let msg = format!("Digest: {}", path);
                if ui.very_verbose {
                    ui.debug(&msg);
                } else {
                    ui.info(&msg);
                }
            }
        }

        let mut ctx = digest::Context::new(alg);
        let mut buf = [0u8; BUFFER_SIZE];
        let mut processed = 0u64;
        loop {
            let count = reader.read(&mut buf)?;
            if count == 0 {
                break;
            }
            ctx.update(&buf[..count]);
            processed += count as u64;

            if let Some(ui) = ui {
                if ui.debug && processed.is_multiple_of(BUFFER_SIZE as u64 * 10) {
                    ui.trace(&format!("Digest: {} bytes", processed));
                }
            }
        }

        if let Some(ui) = ui {
            if ui.very_verbose {
                ui.debug(&format!("Digest complete: {} bytes", processed));
            }
        }

        Ok(base64_engine.encode(ctx.finish().as_ref()))
    }

    /// Colon-separated uppercase SHA-256 fingerprint of a DER certificate.
    pub fn sha256_fingerprint(der: &[u8]) -> String {
        digest::digest(&digest::SHA256, der)
            .as_ref()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Compare fingerprints ignoring separators and case (`AA:BB` or `aabb`).
    pub fn fingerprints_match(a: &str, b: &str) -> bool {
        fn normalize(s: &str) -> String {
            s.chars()
                .filter(|c| c.is_ascii_hexdigit())
                .map(|c| c.to_ascii_uppercase())
                .collect()
        }
        normalize(a) == normalize(b)
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

    #[test]
    fn test_sha256_abc() {
        assert_eq!(
            CryptoEngine::compute_sha256(b"abc"),
            "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
    }

    #[test]
    fn test_stream_sha256() {
        let data = b"stream test data";
        let mut reader = std::io::Cursor::new(data);
        let result = CryptoEngine::compute_stream_sha256(&mut reader).unwrap();
        assert_eq!(result, CryptoEngine::compute_sha256(data));
    }

    #[test]
    fn test_fingerprint_format_and_match() {
        let fp = CryptoEngine::sha256_fingerprint(b"cert");
        assert_eq!(fp.len(), 32 * 3 - 1);
        assert!(fp.contains(':'));

        let plain = fp.replace(':', "").to_lowercase();
        assert!(CryptoEngine::fingerprints_match(&fp, &plain));
        assert!(!CryptoEngine::fingerprints_match(&fp, "00:00"));
    }
}
