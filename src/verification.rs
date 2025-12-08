/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2024 Tiash / @MrCarb0n and Earth Inc.
 * Licensed under the MIT License.
 */

use std::fs::File;
use std::io::Read;
use zip::ZipArchive;

use crate::{
    error::SignerError,
    signing::{CryptoEngine, KeyChain},
    CERT_RSA_NAME, CERT_SF_NAME, MANIFEST_NAME,
};

/// Verifies RSA signatures on signed ZIP/APK/JAR archives.
pub struct ArtifactVerifier;

impl ArtifactVerifier {
    pub fn verify(path: &std::path::Path, keys: &KeyChain) -> Result<bool, SignerError> {
        let public_key = keys
            .public_key
            .as_ref()
            .ok_or(SignerError::Config("Public Key Missing for verification".into()))?;
        let mut archive = ZipArchive::new(File::open(path)?)?;

        let mut signature_bytes = Vec::new();
        archive
            .by_name(CERT_RSA_NAME)
            .map_err(|e| SignerError::Validation(
                format!("No RSA Signature file found ({}): {}", CERT_RSA_NAME, e)
            ))?
            .read_to_end(&mut signature_bytes)?;

        let mut sf_file_bytes = Vec::new();
        archive
            .by_name(CERT_SF_NAME)
            .map_err(|e| SignerError::Validation(
                format!("No SF file found ({}): {}", CERT_SF_NAME, e)
            ))?
            .read_to_end(&mut sf_file_bytes)?;

        public_key.verify(&sf_file_bytes, &signature_bytes)?;

        let mut manifest_bytes = Vec::new();
        archive
            .by_name(MANIFEST_NAME)
            .map_err(|e| SignerError::Validation(
                format!("No Manifest file found ({}): {}", MANIFEST_NAME, e)
            ))?
            .read_to_end(&mut manifest_bytes)?;

        let manifest_hash = CryptoEngine::compute_sha1(&manifest_bytes);
        let sf_content = String::from_utf8_lossy(&sf_file_bytes);

        if !sf_content.contains(&format!("SHA1-Digest-Manifest: {}", manifest_hash)) {
            return Err(SignerError::Validation("Manifest hash in SF file does not match".into()));
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
            if name.ends_with('/') || name.starts_with("META-INF/") {
                continue;
            }
            let mut hasher_input = Vec::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 { break; }
                hasher_input.extend_from_slice(&buf[..n]);
            }
            let digest = CryptoEngine::compute_sha1(&hasher_input);
            file_map.insert(name, digest);
        }

        for (name, file_digest) in &file_map {
            let m_digest = manifest_entries.get(name).ok_or_else(|| SignerError::Validation(
                format!("Manifest missing entry for {}", name)
            ))?;
            if m_digest != file_digest {
                return Err(SignerError::Validation(format!(
                    "Manifest digest mismatch for {}", name
                )));
            }
        }

        for (name, _) in &manifest_entries {
            if !file_map.contains_key(name) {
                return Err(SignerError::Validation(format!(
                    "Manifest references missing file {}", name
                )));
            }
        }

        for (name, m_digest) in &manifest_entries {
            let entry_bytes = Self::make_manifest_entry_bytes(name, m_digest);
            let entry_hash = CryptoEngine::compute_sha1(&entry_bytes);
            let sf_digest = sf_entries.get(name).ok_or_else(|| SignerError::Validation(
                format!("SF missing entry for {}", name)
            ))?;
            if sf_digest != &entry_hash {
                return Err(SignerError::Validation(format!(
                    "SF digest mismatch for {}", name
                )));
            }
        }

        Ok(true)
    }

    fn unfold_lines(s: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new(); // <--- FIXED TYPE ANNOTATION HERE
        for line in s.split("\r\n") {
            if let Some(last) = out.last_mut() {
                if line.starts_with(' ') {
                    last.push_str(&line[1..]);
                    continue;
                }
            }
            out.push(line.to_string());
        }
        out
    }

    fn parse_entries(lines: &[String]) -> std::collections::BTreeMap<String, String> {
        let mut map = std::collections::BTreeMap::new();
        let mut cur_name: Option<String> = None;
        let mut cur_digest: Option<String> = None;
        for line in lines {
            if line.is_empty() {
                if let (Some(n), Some(d)) = (cur_name.take(), cur_digest.take()) {
                    map.insert(n, d);
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("Name: ") {
                cur_name = Some(rest.to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("SHA1-Digest: ") {
                cur_digest = Some(rest.to_string());
                continue;
            }
        }
        if let (Some(n), Some(d)) = (cur_name.take(), cur_digest.take()) {
            map.insert(n, d);
        }
        map
    }

    fn write_manifest_line(out: &mut Vec<u8>, key: &str, value: &str) {
        let line = format!("{}: {}", key, value).into_bytes();
        let mut cursor = 0;
        let len = line.len();
        while cursor < len {
            let remaining = len - cursor;
            let limit = if cursor == 0 { 72 } else { 71 };
            let chunk_size = std::cmp::min(remaining, limit);
            if cursor > 0 { out.push(b' '); }
            out.extend_from_slice(&line[cursor..cursor + chunk_size]);
            out.extend_from_slice(b"\r\n");
            cursor += chunk_size;
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
