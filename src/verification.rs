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

pub struct ArtifactVerifier;

impl ArtifactVerifier {
    pub fn verify(path: &std::path::Path, keys: &KeyChain) -> Result<bool, SignerError> {
        let public_key = keys
            .public_key
            .as_ref()
            .ok_or(SignerError::Config("Public Key Missing for verification".into()))?;
        let mut archive = ZipArchive::new(File::open(path)?)?;

        let mut signature_bytes = Vec::new();
        if archive.by_name(CERT_RSA_NAME).is_err() {
            return Err(SignerError::Validation("No RSA Signature file found".into()));
        }
        archive.by_name(CERT_RSA_NAME)?.read_to_end(&mut signature_bytes)?;

        let mut sf_file_bytes = Vec::new();
        if archive.by_name(CERT_SF_NAME).is_err() {
            return Err(SignerError::Validation("No SF file found".into()));
        }
        archive.by_name(CERT_SF_NAME)?.read_to_end(&mut sf_file_bytes)?;

        // Verification algorithm computes SHA-256 internally for RSA_PKCS1_SHA256
        public_key.verify(&sf_file_bytes, &signature_bytes)?;

        let mut manifest_bytes = Vec::new();
        if archive.by_name(MANIFEST_NAME).is_err() {
            return Err(SignerError::Validation("No Manifest file found".into()));
        }
        archive.by_name(MANIFEST_NAME)?.read_to_end(&mut manifest_bytes)?;

        let manifest_hash = CryptoEngine::compute_sha1(&manifest_bytes);
        let sf_content = String::from_utf8_lossy(&sf_file_bytes);

        if !sf_content.contains(&format!("SHA1-Digest-Manifest: {}", manifest_hash)) {
            return Err(SignerError::Validation("Manifest hash in SF file does not match".into()));
        }

        Ok(true)
    }
}
