/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use std::fs::File;
use std::io::Read;
use zip::ZipArchive;

use crate::{
    crypto::CryptoEngine, error::SignerError, keys::KeyChain, CERT_RSA_NAME, CERT_SF_NAME,
    MANIFEST_NAME,
};

/// Verifies signatures on Android archive files
pub struct ArtifactVerifier;

impl ArtifactVerifier {
    /// Check if an archive's signature is valid
    pub fn verify(
        path: &std::path::Path,
        keys: &KeyChain,
        ui: &crate::ui::Ui,
    ) -> Result<bool, SignerError> {
        ui.verbose(&format!(
            "Starting verification for archive: {}",
            path.display()
        ));

        let public_key = keys.public_key.as_ref().ok_or(SignerError::Config(
            "Public Key Missing for verification".into(),
        ))?;

        ui.verbose("Loading signature verification key");
        let mut archive = ZipArchive::new(File::open(path)?)?;
        ui.verbose(&format!("Opened archive with {} entries", archive.len()));

        let mut signature_bytes = Vec::new();
        ui.verbose(&format!("Reading RSA signature from: {}", CERT_RSA_NAME));
        archive
            .by_name(CERT_RSA_NAME)
            .map_err(|_| {
                SignerError::Validation(format!(
                    "No RSA Signature file found ({}). Archive may not be properly signed.",
                    CERT_RSA_NAME
                ))
            })?
            .read_to_end(&mut signature_bytes)?;
        ui.verbose(&format!(
            "Read RSA signature ({} bytes)",
            signature_bytes.len()
        ));

        let mut sf_file_bytes = Vec::new();
        ui.verbose(&format!("Reading signature file from: {}", CERT_SF_NAME));
        archive
            .by_name(CERT_SF_NAME)
            .map_err(|_| {
                SignerError::Validation(format!(
                    "No Signature File found ({}). Archive may not be properly signed.",
                    CERT_SF_NAME
                ))
            })?
            .read_to_end(&mut sf_file_bytes)?;
        ui.verbose(&format!(
            "Read signature file ({} bytes)",
            sf_file_bytes.len()
        ));

        ui.verbose("Verifying RSA signature against signature file...");
        if let Err(e) = public_key.verify(&sf_file_bytes, &signature_bytes) {
            ui.verbose(&format!("RSA signature verification failed: {}", e));
            return Err(SignerError::Validation(
                format!("Signature verification failed: {}. This could be due to: invalid certificate, corrupted signature, mismatched key pair, or archive tampering.", e)
            ));
        }
        ui.verbose("RSA signature verification passed");

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
            let entry_bytes = Self::make_manifest_entry_bytes(name, m_digest);
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

    fn write_manifest_line(out: &mut Vec<u8>, key: &str, value: &str) {
        // Check if this field should not be wrapped according to JAR specification
        // Using the same comprehensive check as in processor module
        let should_not_wrap = key == "Name"
            || key.contains("-Digest")
            || key.contains("_Digest")
            || key == "SHA1-Digest-Manifest"
            || key == "SHA-256-Digest-Manifest"
            || key == "MD5-Digest-Manifest";

        if should_not_wrap {
            // Write the full line without wrapping for Name fields, digest values, etc.
            // Explicitly avoid any potential for line breaks by joining key, value with colon-space
            let line = format!("{}: {}", key, value);
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        } else {
            // Apply line wrapping for other fields (RFC 2822-style)
            let line = format!("{}: {}", key, value).into_bytes();
            let mut cursor = 0;
            let len = line.len();
            while cursor < len {
                let remaining = len - cursor;
                let limit = if cursor == 0 { 72 } else { 71 };
                let chunk_size = std::cmp::min(remaining, limit);
                if cursor > 0 {
                    out.push(b' ');
                }
                out.extend_from_slice(&line[cursor..cursor + chunk_size]);
                out.extend_from_slice(b"\r\n");
                cursor += chunk_size;
            }
        }
    }

    fn make_manifest_entry_bytes(name: &str, hash: &str) -> Vec<u8> {
        let mut entry = Vec::new();
        Self::write_manifest_line(&mut entry, "Name", name);
        Self::write_manifest_line(&mut entry, "SHA1-Digest", hash);
        entry.extend_from_slice(b"\r\n");
        entry
    }
}
