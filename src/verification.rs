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

use std::fs::File;
use std::io::Read;
use zip::ZipArchive;

use crate::{
    crypto::CryptoEngine, error::SignerError, keys::KeyChain, pkcs7, processor::ArtifactProcessor,
    CERT_RSA_NAME, CERT_SF_NAME, MANIFEST_NAME,
};

/// Error message returned when a candidate archive has no RSA signature
/// entry (i.e. it is not signed or the signature has been stripped).
pub const ERR_NO_RSA_SIGNATURE: &str = "No RSA Signature file found";

/// Error message returned when a candidate archive has no .SF (signature
/// file) entry, which is required for a complete signing chain.
pub const ERR_NO_SIGNATURE_FILE: &str = "No Signature File found";

/// Error message returned when a candidate archive has no MANIFEST.MF
/// entry, which is the root of the per-entry hash chain.
pub const ERR_NO_MANIFEST: &str = "No Manifest file found";

/// Verifies signatures on Android archive files
pub struct ArtifactVerifier;

impl ArtifactVerifier {
    /// Check if an archive's signature is valid
    pub fn verify(
        path: &std::path::Path,
        keys: &KeyChain,
        ui: &crate::ui::Ui,
    ) -> Result<bool, SignerError> {
        ui.debug(&format!(
            "Starting verification for archive: {}",
            path.display()
        ));

        let public_key = keys.public_key.as_ref().ok_or(SignerError::Config(
            "Public Key Missing for verification".into(),
        ))?;

        ui.debug("Loading signature verification key");
        let mut archive = ZipArchive::new(File::open(path)?)?;
        ui.info(&format!("Opened archive with {} entries", archive.len()));

        let mut signature_bytes = Vec::new();
        ui.debug(&format!("Reading RSA signature from: {}", CERT_RSA_NAME));
        archive
            .by_name(CERT_RSA_NAME)
            .map_err(|_| {
                SignerError::Validation(format!(
                    "No RSA Signature file found ({}). Archive may not be properly signed.",
                    CERT_RSA_NAME
                ))
            })?
            .read_to_end(&mut signature_bytes)?;
        ui.debug(&format!(
            "Read RSA signature ({} bytes)",
            signature_bytes.len()
        ));

        let mut sf_file_bytes = Vec::new();
        ui.debug(&format!("Reading signature file from: {}", CERT_SF_NAME));
        archive
            .by_name(CERT_SF_NAME)
            .map_err(|_| {
                SignerError::Validation(format!(
                    "No Signature File found ({}). Archive may not be properly signed.",
                    CERT_SF_NAME
                ))
            })?
            .read_to_end(&mut sf_file_bytes)?;
        ui.debug(&format!(
            "Read signature file ({} bytes)",
            sf_file_bytes.len()
        ));

        ui.debug("Extracting PKCS7 signature data...");
        let signer_info = pkcs7::extract_signer_info(&signature_bytes)?;

        ui.debug("Verifying RSA signature over PKCS7 authenticated attributes...");
        if let Err(e) = public_key.verify(&signer_info.auth_attrs_der, &signer_info.signature) {
            ui.debug(&format!("RSA signature verification failed: {}", e));
            return Err(SignerError::Validation(
                format!("Signature verification failed: {}. This could be due to: invalid certificate, corrupted signature, mismatched key pair, or archive tampering.", e)
            ));
        }
        ui.debug("RSA signature verification passed");

        ui.debug("Verifying SF file digest matches PKCS7 messageDigest...");
        let sf_digest = ring::digest::digest(&ring::digest::SHA256, &sf_file_bytes);
        if sf_digest.as_ref() != signer_info.message_digest.as_slice() {
            return Err(SignerError::Validation(format!(
                "SF file digest mismatch. Computed: {:?}, Expected: {:?}",
                sf_digest.as_ref(),
                signer_info.message_digest
            )));
        }
        ui.debug("SF file digest matches PKCS7 messageDigest");

        let mut manifest_bytes = Vec::new();
        archive
            .by_name(MANIFEST_NAME)
            .map_err(|_| {
                SignerError::Validation(format!(
                    "No Manifest file found ({}). Archive may not be properly signed.",
                    MANIFEST_NAME
                ))
            })?
            .read_to_end(&mut manifest_bytes)?;

        let manifest_hash = CryptoEngine::compute_sha1(&manifest_bytes);
        let sf_content = String::from_utf8_lossy(&sf_file_bytes);

        if !sf_content.contains(&format!("SHA1-Digest-Manifest: {}", manifest_hash)) {
            return Err(SignerError::Validation(
                format!("Manifest hash mismatch. The manifest file ({}) does not match the hash stored in the signature file ({}). Archive may be corrupted or tampered with.", MANIFEST_NAME, CERT_SF_NAME)
            ));
        }

        let manifest_str = String::from_utf8_lossy(&manifest_bytes);
        let unfolded_manifest_lines = Self::unfold_lines(manifest_str.as_ref());
        let manifest_entries = Self::parse_entries(&unfolded_manifest_lines);

        let sf_str = String::from_utf8_lossy(&sf_file_bytes);
        let unfolded_sf_lines = Self::unfold_lines(sf_str.as_ref());
        let sf_entries = Self::parse_entries(&unfolded_sf_lines);

        let mut file_map = std::collections::BTreeMap::new();
        let mut buf = [0u8; crate::BUFFER_SIZE];
        for i in 0..archive.len() {
            let mut f = archive.by_index(i)?;
            let name = f.name().to_string();
            if name.ends_with('/') {
                continue;
            }

            if name.starts_with("META-INF/")
                && (name == crate::MANIFEST_NAME
                    || name == crate::CERT_SF_NAME
                    || name == crate::CERT_RSA_NAME
                    || name == crate::CERT_PUBLIC_KEY_NAME
                    || name.ends_with("/MANIFEST.MF")
                    || name.ends_with(".SF")
                    || name.ends_with(".RSA")
                    || name.ends_with(".DSA")
                    || name.ends_with(".EC"))
            {
                continue;
            }

            let mut hasher_input = Vec::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher_input.extend_from_slice(&buf[..n]);
            }
            let digest = CryptoEngine::compute_sha1(&hasher_input);
            file_map.insert(name, digest);
        }

        for (name, file_digest) in &file_map {
            let m_digest = manifest_entries.get(name).ok_or_else(|| {
                SignerError::Validation(format!("File '{}' exists in archive but is missing from manifest. Archive may be corrupted or tampered with.", name))
            })?;
            if m_digest != file_digest {
                return Err(SignerError::Validation(format!(
                    "Digest mismatch for file '{}'. Computed digest: {}, Manifest digest: {}. Archive may be corrupted or tampered with.",
                    name, file_digest, m_digest
                )));
            }
        }

        for name in manifest_entries.keys() {
            if !file_map.contains_key(name) {
                return Err(SignerError::Validation(format!(
                    "Manifest references file '{}' that is missing from archive. Archive may be corrupted or tampered with.",
                    name
                )));
            }
        }

        for (name, m_digest) in &manifest_entries {
            let entry_bytes = ArtifactProcessor::create_manifest_entry(name, m_digest);
            let entry_hash = CryptoEngine::compute_sha1(&entry_bytes);
            let sf_digest = sf_entries.get(name).ok_or_else(|| {
                SignerError::Validation(format!(
                    "File '{}' exists in manifest but is missing from signature file ({}).",
                    name, CERT_SF_NAME
                ))
            })?;
            if sf_digest != &entry_hash {
                return Err(SignerError::Validation(format!(
                    "Signature file digest mismatch for '{}'. Entry hash: {}, Signature file hash: {}. Archive may be corrupted or tampered with.",
                    name, entry_hash, sf_digest
                )));
            }
        }

        Ok(true)
    }

    fn unfold_lines(s: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for line in s.split("\r\n") {
            if let Some(last) = out.last_mut().filter(|_| line.starts_with(' ')) {
                if let Some(stripped) = line.strip_prefix(' ') {
                    last.push_str(stripped);
                }
            } else {
                out.push(line.to_string());
            }
        }
        out
    }

    fn parse_entries(lines: &[String]) -> std::collections::BTreeMap<String, String> {
        let mut map = std::collections::BTreeMap::new();
        let mut cur_name: Option<String> = None;
        let mut cur_digest: Option<String> = None;

        for line in lines {
            if line.is_empty() {
                if let (Some(name), Some(digest)) = (cur_name.take(), cur_digest.take()) {
                    map.insert(name, digest);
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("Name: ") {
                cur_name = Some(rest.to_string());
            } else if let Some(rest) = line.strip_prefix("SHA1-Digest: ") {
                cur_digest = Some(rest.to_string());
            }
        }

        if let (Some(name), Some(digest)) = (cur_name.take(), cur_digest.take()) {
            map.insert(name, digest);
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unfold_lines_no_continuation() {
        // split("\r\n") on string ending with \r\n produces trailing empty entry
        let lines = ArtifactVerifier::unfold_lines("Name: test.txt\r\nSHA1-Digest: abc\r\n");
        assert_eq!(lines[0], "Name: test.txt");
        assert_eq!(lines[1], "SHA1-Digest: abc");
        assert_eq!(lines[2], "");
    }

    #[test]
    fn test_unfold_lines_with_continuation() {
        let s = "Created-By: ZipSigner\r\n Test\r\n";
        let lines = ArtifactVerifier::unfold_lines(s);
        assert_eq!(lines[0], "Created-By: ZipSignerTest");
        assert_eq!(lines[1], "");
    }

    #[test]
    fn test_unfold_lines_multiple_continuations() {
        let s = "Long: part1\r\n part2\r\n part3\r\n";
        let lines = ArtifactVerifier::unfold_lines(s);
        assert_eq!(lines[0], "Long: part1part2part3");
        assert_eq!(lines[1], "");
    }

    #[test]
    fn test_unfold_lines_no_trailing_newline() {
        // Without trailing \r\n, no empty entry at end
        let lines = ArtifactVerifier::unfold_lines("Name: test.txt\r\nSHA1-Digest: abc");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "Name: test.txt");
        assert_eq!(lines[1], "SHA1-Digest: abc");
    }

    #[test]
    fn test_parse_entries_single() {
        let lines = vec!["Name: f.txt".into(), "SHA1-Digest: d1".into(), "".into()];
        let map = ArtifactVerifier::parse_entries(&lines);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("f.txt").unwrap(), "d1");
    }

    #[test]
    fn test_parse_entries_multiple() {
        let lines = vec![
            "Name: a.txt".into(),
            "SHA1-Digest: da".into(),
            "".into(),
            "Name: b.txt".into(),
            "SHA1-Digest: db".into(),
            "".into(),
        ];
        let map = ArtifactVerifier::parse_entries(&lines);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("a.txt").unwrap(), "da");
        assert_eq!(map.get("b.txt").unwrap(), "db");
    }

    #[test]
    fn test_parse_entries_empty() {
        let lines = vec!["Manifest-Version: 1.0".into()];
        let map = ArtifactVerifier::parse_entries(&lines);
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_entries_skips_non_name_digest() {
        let lines = vec![
            "Name: x.txt".into(),
            "SHA1-Digest: dx".into(),
            "Extra-Field: junk".into(),
            "".into(),
        ];
        let map = ArtifactVerifier::parse_entries(&lines);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("x.txt").unwrap(), "dx");
    }
}
