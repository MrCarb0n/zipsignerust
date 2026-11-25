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

use std::io::{Read, Seek};
use zip::ZipArchive;

use crate::{crypto::CryptoEngine, error::SignerError, keys::KeyChain, pkcs7, MANIFEST_NAME};
use x509_parser::prelude::FromDer;

/// Error message returned when a candidate archive has no RSA signature
/// entry (i.e. it is not signed or the signature has been stripped).
pub const ERR_NO_RSA_SIGNATURE: &str = "No RSA Signature file found";

/// Digest fields accepted in MANIFEST.MF / *.SF, strongest first.
const DIGEST_FIELDS: [(&str, &ring::digest::Algorithm); 4] = [
    ("SHA-512-Digest", &ring::digest::SHA512),
    ("SHA-384-Digest", &ring::digest::SHA384),
    ("SHA-256-Digest", &ring::digest::SHA256),
    ("SHA1-Digest", &ring::digest::SHA1_FOR_LEGACY_USE_ONLY),
];

/// Digest algorithm for a manifest/SF digest field name.
fn digest_algorithm_for(field: &str) -> Option<&'static ring::digest::Algorithm> {
    DIGEST_FIELDS
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, alg)| *alg)
}

/// Verifies signatures on Android archive files
pub struct ArtifactVerifier;

impl ArtifactVerifier {
    /// Check if an archive's signature is valid
    pub fn verify(
        path: &std::path::Path,
        keys: &KeyChain,
        ui: &crate::ui::Ui,
    ) -> Result<bool, SignerError> {
        Self::verify_with_pin(path, keys, ui, None)
    }

    /// Check signature validity and optionally bind to embedded signer certificate fingerprint.
    pub fn verify_with_pin(
        path: &std::path::Path,
        keys: &KeyChain,
        ui: &crate::ui::Ui,
        pin: Option<&str>,
    ) -> Result<bool, SignerError> {
        Self::verify_trusted(path, Some(keys), ui, pin)
    }

    pub(crate) fn verify_trusted(
        path: &std::path::Path,
        keys: Option<&KeyChain>,
        ui: &crate::ui::Ui,
        pin: Option<&str>,
    ) -> Result<bool, SignerError> {
        let trusted_key = keys
            .map(|keys| {
                keys.public_key
                    .as_ref()
                    .ok_or_else(|| SignerError::Config("Missing trusted public key".into()))
            })
            .transpose()?;
        if trusted_key.is_none() && pin.is_none() {
            return Err(SignerError::Config(
                "A trusted key or certificate pin is required".into(),
            ));
        }
        ui.debug(&format!(
            "Starting verification for archive: {}",
            path.display()
        ));

        let mut archive = crate::processor::ArtifactProcessor::open_zip(path)?;
        ui.info(&format!("Opened archive with {} entries", archive.len()));

        let (sf_name, block_name) = Self::find_signature_files(&mut archive)?;
        let mut signature_bytes = Vec::new();
        ui.debug(&format!("Reading signature block from: {}", block_name));
        archive
            .by_name(&block_name)?
            .read_to_end(&mut signature_bytes)?;
        let mut sf_file_bytes = Vec::new();
        ui.debug(&format!("Reading signature file from: {}", sf_name));
        archive.by_name(&sf_name)?.read_to_end(&mut sf_file_bytes)?;

        ui.debug("Extracting PKCS7 signature data...");
        let signer_info = pkcs7::extract_signer_info(&signature_bytes)?;
        ui.debug(&format!(
            "PKCS7 digest algorithm: {:?}",
            signer_info.digest_algorithm
        ));

        let signer_cert = signer_info.signer_cert_der;
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&signer_cert)
            .map_err(|e| SignerError::Validation(format!("Invalid signer certificate: {e}")))?;
        if let Some(expected) = pin {
            let actual = CryptoEngine::sha256_fingerprint(&signer_cert);
            if !CryptoEngine::fingerprints_match(&actual, expected) {
                return Err(SignerError::Validation(format!(
                    "Certificate fingerprint mismatch: expected {}, got {}",
                    expected, actual
                )));
            }
            ui.info(&format!("Certificate pin matched: {}", actual));
        }
        let public_key = cert.public_key().subject_public_key.data.as_ref();
        if trusted_key.is_some_and(|key| key.as_ref() != public_key) {
            return Err(SignerError::Validation(
                "Embedded signer does not match the trusted public key".into(),
            ));
        }
        let signed_payload = if signer_info.signed_data.is_empty() {
            &sf_file_bytes
        } else {
            &signer_info.signed_data
        };
        ui.debug("Verifying RSA signature...");
        let verifier = ring::signature::UnparsedPublicKey::new(
            signer_info.digest_algorithm.verification_algorithm(),
            public_key,
        );
        if let Err(e) = verifier.verify(signed_payload, &signer_info.signature) {
            ui.debug(&format!("RSA signature verification failed: {}", e));
            return Err(SignerError::Validation(format!(
                "Signature verification failed: {}. This could be due to: invalid certificate, corrupted signature, mismatched key pair, or archive tampering.",
                e
            )));
        }
        ui.debug("RSA signature verification passed");

        if let Some(expected) = signer_info.message_digest.as_ref() {
            ui.debug("Verifying SF file digest matches PKCS7 messageDigest...");
            let sf_digest =
                ring::digest::digest(signer_info.digest_algorithm.digest(), &sf_file_bytes);
            if sf_digest.as_ref() != expected.as_slice() {
                return Err(SignerError::Validation(format!(
                    "SF file digest mismatch. Computed: {:?}, Expected: {:?}",
                    sf_digest.as_ref(),
                    expected
                )));
            }
            ui.debug("SF file digest matches PKCS7 messageDigest");
        }

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

        let sf_str = String::from_utf8_lossy(&sf_file_bytes);
        let unfolded_sf_lines = Self::unfold_lines(sf_str.as_ref());
        let has_manifest_hash = unfolded_sf_lines.iter().any(|line| {
            DIGEST_FIELDS
                .iter()
                .any(|(f, _)| line.starts_with(&format!("{}-Manifest: ", f)))
        });
        if has_manifest_hash {
            let manifest_hash_ok = DIGEST_FIELDS.iter().any(|(field, alg)| {
                let expected = format!(
                    "{}-Manifest: {}",
                    field,
                    CryptoEngine::compute_digest(alg, &manifest_bytes)
                );
                unfolded_sf_lines.iter().any(|line| line == &expected)
            });
            if !manifest_hash_ok {
                return Err(SignerError::Validation(format!(
                    "Manifest hash mismatch. The manifest file ({}) does not match the hash stored in the signature file ({}). Archive may be corrupted or tampered with.",
                    MANIFEST_NAME, sf_name
                )));
            }
        }

        let manifest_str = String::from_utf8_lossy(&manifest_bytes);
        let unfolded_manifest_lines = Self::unfold_lines(manifest_str.as_ref());
        let manifest_entries = Self::parse_entries(&unfolded_manifest_lines);
        let sf_entries = Self::parse_entries(&unfolded_sf_lines);

        let mut file_map = std::collections::BTreeMap::new();
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..archive.len() {
            let mut f = archive.by_index(i)?;
            let name = f.name().to_string();
            if !seen.insert(name.clone()) {
                return Err(SignerError::Validation(format!(
                    "Duplicate archive entry '{}'",
                    name
                )));
            }
            if name.ends_with('/') {
                continue;
            }

            if crate::processor::ArtifactProcessor::is_sig_file(&name) {
                continue;
            }

            let digest = match manifest_entries
                .get(&name)
                .and_then(|(field, _)| digest_algorithm_for(field))
            {
                Some(alg) => CryptoEngine::compute_stream_digest(&mut f, alg, None, None)?,
                None => CryptoEngine::compute_stream_sha256(&mut f)?,
            };
            file_map.insert(name, digest);
        }

        for (name, file_digest) in &file_map {
            let (_, m_digest) = manifest_entries.get(name).ok_or_else(|| {
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

        let manifest_sections: std::collections::BTreeMap<String, Vec<u8>> =
            Self::raw_manifest_entries(&manifest_bytes)
                .into_iter()
                .collect();

        for name in manifest_entries.keys() {
            let section = manifest_sections.get(name).ok_or_else(|| {
                SignerError::Validation(format!(
                    "Manifest entry for '{}' could not be located in {}.",
                    name, MANIFEST_NAME
                ))
            })?;
            let (sf_field, sf_digest) = sf_entries.get(name).ok_or_else(|| {
                SignerError::Validation(format!(
                    "File '{}' exists in manifest but is missing from signature file ({}).",
                    name, sf_name
                ))
            })?;
            let alg = digest_algorithm_for(sf_field).ok_or_else(|| {
                SignerError::Validation(format!(
                    "Unsupported signature digest field '{}'.",
                    sf_field
                ))
            })?;
            let entry_hash = CryptoEngine::compute_digest(alg, section);
            if sf_digest != &entry_hash {
                return Err(SignerError::Validation(format!(
                    "Signature file digest mismatch for '{}'. Entry hash: {}, Signature file hash: {}. Archive may be corrupted or tampered with.",
                    name, entry_hash, sf_digest
                )));
            }
        }

        Ok(true)
    }

    fn find_signature_files(
        archive: &mut ZipArchive<impl Read + Seek>,
    ) -> Result<(String, String), SignerError> {
        let mut sf = None;
        for i in 0..archive.len() {
            let name = archive.by_index(i)?.name().to_string();
            let Some(rest) = name.strip_prefix("META-INF/") else {
                continue;
            };
            if rest.contains('/') {
                continue;
            }
            if let Some(base) = rest.strip_suffix(".SF") {
                sf = Some((base.to_string(), name));
                break;
            }
        }
        let (base, sf_name) = sf.ok_or_else(|| {
            SignerError::Validation(format!(
                "{}. Archive may not be properly signed.",
                ERR_NO_RSA_SIGNATURE
            ))
        })?;
        for ext in [".RSA", ".DSA", ".EC"] {
            let cand = format!("META-INF/{}{}", base, ext);
            if archive.by_name(&cand).is_ok() {
                return Ok((sf_name, cand));
            }
        }
        Err(SignerError::Validation(format!(
            "{} (META-INF/{}.(RSA|DSA|EC)). Archive may not be properly signed.",
            ERR_NO_RSA_SIGNATURE, base
        )))
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

    /// Raw bytes of each MANIFEST.MF entry section, keyed by Name, including
    /// the blank line that terminates the section — those exact bytes are what
    /// the *.SF per-entry digest covers.
    fn raw_manifest_entries(manifest: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut rest = manifest;
        while !rest.is_empty() {
            let (section, tail) = match rest.windows(4).position(|w| w == b"\r\n\r\n") {
                Some(idx) => rest.split_at(idx + 4),
                None => (rest, &rest[rest.len()..]),
            };
            rest = tail;
            let Some(name_line) = section.strip_prefix(b"Name: ") else {
                continue;
            };
            // Unfold the Name header; continued lines start with a space.
            let mut name = String::new();
            let mut first = true;
            for line in name_line.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                let piece = if first {
                    first = false;
                    line
                } else if let Some(rest) = line.strip_prefix(b" ") {
                    rest
                } else {
                    break;
                };
                name.push_str(&String::from_utf8_lossy(piece));
            }
            out.push((name, section.to_vec()));
        }
        out
    }

    /// name -> (digest field name, digest). Strongest digest wins.
    fn parse_entries(lines: &[String]) -> std::collections::BTreeMap<String, (String, String)> {
        let mut map = std::collections::BTreeMap::new();
        let mut cur_name: Option<String> = None;
        let mut cur_digest: Option<(String, String)> = None;

        for line in lines {
            if line.is_empty() {
                if let (Some(name), Some(digest)) = (cur_name.take(), cur_digest.take()) {
                    map.insert(name, digest);
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("Name: ") {
                cur_name = Some(rest.to_string());
            } else if let Some((field, value)) = line.split_once(": ") {
                if let Some(rank) = DIGEST_FIELDS.iter().position(|(name, _)| *name == field) {
                    let keep = cur_digest
                        .as_ref()
                        .and_then(|(current, _)| {
                            DIGEST_FIELDS
                                .iter()
                                .position(|(name, _)| *name == current.as_str())
                        })
                        .is_none_or(|current_rank| rank < current_rank);
                    if keep {
                        cur_digest = Some((field.to_string(), value.to_string()));
                    }
                }
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
        assert_eq!(map.get("f.txt").unwrap().1, "d1");
        assert_eq!(map.get("f.txt").unwrap().0, "SHA1-Digest");
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
        assert_eq!(map.get("a.txt").unwrap().1, "da");
        assert_eq!(map.get("b.txt").unwrap().1, "db");
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
        assert_eq!(map.get("x.txt").unwrap().1, "dx");
    }

    #[test]
    fn test_parse_entries_prefers_sha256() {
        let lines = vec![
            "Name: x.txt".into(),
            "SHA1-Digest: old".into(),
            "SHA-256-Digest: new".into(),
            "".into(),
        ];
        let map = ArtifactVerifier::parse_entries(&lines);
        assert_eq!(map.get("x.txt").unwrap().0, "SHA-256-Digest");
        assert_eq!(map.get("x.txt").unwrap().1, "new");
    }

    #[test]
    fn test_parse_entries_accepts_sha384_and_sha512() {
        let lines = vec![
            "Name: x.txt".into(),
            "SHA-256-Digest: old".into(),
            "SHA-384-Digest: mid".into(),
            "SHA-512-Digest: new".into(),
            "".into(),
        ];
        let map = ArtifactVerifier::parse_entries(&lines);
        assert_eq!(map.get("x.txt").unwrap().0, "SHA-512-Digest");
        assert_eq!(map.get("x.txt").unwrap().1, "new");
    }

    #[test]
    fn test_raw_manifest_entries_includes_terminating_blank_line() {
        let manifest = b"Manifest-Version: 1.0\r\nCreated-By: test\r\n\r\nName: a.txt\r\nSHA-384-Digest: ab\r\n cd\r\n\r\n";
        let entries = ArtifactVerifier::raw_manifest_entries(manifest);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "a.txt");
        assert_eq!(
            entries[0].1,
            b"Name: a.txt\r\nSHA-384-Digest: ab\r\n cd\r\n\r\n".to_vec()
        );

        // A folded Name header still yields the full unfolded name.
        let folded = b"Manifest-Version: 1.0\r\n\r\nName: /very/long/\r\n path/name.txt\r\nSHA-256-Digest: x\r\n\r\n";
        let entries = ArtifactVerifier::raw_manifest_entries(folded);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "/very/long/path/name.txt");
    }
}
