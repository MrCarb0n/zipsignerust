/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2024 Tiash / @MrCarb0n and Earth Inc.
 * Licensed under the MIT License.
 */

use ::pem as pem_crate;
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use crc32fast::Hasher as Crc32;
use filetime::{set_file_times, FileTime};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{self, RsaKeyPair, UnparsedPublicKey},
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};
use tempfile::tempdir;
use x509_parser::prelude::*;
use zip::{
    write::{FileOptions, ZipWriter},
    CompressionMethod, DateTime, ZipArchive,
};

use crate::{
    error::SignerError, ui, APP_NAME, BUFFER_SIZE, CERT_RSA_NAME, CERT_SF_NAME, MANIFEST_NAME,
};

const RSA_SIGNATURE_SCHEME: &dyn signature::RsaEncoding = &signature::RSA_PKCS1_SHA256;

const RSA_VERIFICATION_ALGORITHM: &'static dyn signature::VerificationAlgorithm =
    &signature::RSA_PKCS1_2048_8192_SHA256;

/// Cryptographic engine for computing SHA-1 digests.
/// Used for generating manifest and signature file hashes.
pub struct CryptoEngine;

impl CryptoEngine {
    pub fn compute_sha1(data: &[u8]) -> String {
        let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
        base64_engine.encode(digest.as_ref())
    }

    pub fn compute_stream_sha1<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            context.update(&buffer[..count]);
        }
        let digest = context.finish();
        Ok(base64_engine.encode(digest.as_ref()))
    }
}

/// Container for RSA key pair and certificate metadata.
/// Manages private/public keys and extracts timestamp from certificate.
pub struct KeyChain {
    pub private_key: Option<RsaKeyPair>,
    pub public_key: Option<UnparsedPublicKey<Vec<u8>>>,
    pub cert_not_before: Option<DateTime>,
}

impl KeyChain {
    pub fn new(priv_path: Option<&Path>, pub_path: Option<&Path>) -> Result<Self, SignerError> {
        let private_key = if let Some(path) = priv_path {
            Self::check_key_permissions(path)?;
            let pem_data = fs::read(path)?;
            let pem = pem_crate::parse(pem_data)?;
            RsaKeyPair::from_pkcs8(&pem.contents)
                .map_err(|e| SignerError::Config(format!("Invalid Private Key: {}", e)))
                .ok()
        } else {
            let pem = pem_crate::parse(crate::default_keys::PRIVATE_KEY.as_bytes())?;
            RsaKeyPair::from_pkcs8(&pem.contents)
                .map_err(|e| SignerError::Config(format!("Invalid Default Private Key: {}", e)))
                .ok()
        };

        let (public_key, cert_not_before) = if let Some(path) = pub_path {
            let pem_data = fs::read(path)?;
            let pem = pem_crate::parse(pem_data)?;
            let der = pem.contents;
            let cert = X509Certificate::from_der(&der)
                .map_err(|e| SignerError::Config(format!("Invalid certificate: {:?}", e)))?
                .1;
            let pk_der = cert.public_key().subject_public_key.data.to_vec();
            let nb = Some(Self::asn1_to_zip_datetime(cert.validity().not_before));
            (Some(UnparsedPublicKey::new(RSA_VERIFICATION_ALGORITHM, pk_der)), nb)
        } else {
            let pem = pem_crate::parse(crate::default_keys::PUBLIC_KEY.as_bytes())?;
            let der = pem.contents;
            let cert = X509Certificate::from_der(&der)
                .map_err(|e| SignerError::Config(format!("Invalid default certificate: {:?}", e)))?
                .1;
            let pk_der = cert.public_key().subject_public_key.data.to_vec();
            let nb = Some(Self::asn1_to_zip_datetime(cert.validity().not_before));
            (Some(UnparsedPublicKey::new(RSA_VERIFICATION_ALGORITHM, pk_der)), nb)
        };

        if private_key.is_none() && public_key.is_none() {
            return Err(SignerError::Config(
                "Failed to load any keys (both custom and default failed).".into(),
            ));
        }

        Ok(Self { private_key, public_key, cert_not_before })
    }

    pub fn get_reproducible_timestamp(&self) -> DateTime {
        if let Some(dt) = &self.cert_not_before {
            return *dt;
        }
        DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap()
    }

    #[cfg(unix)]
    fn check_key_permissions(path: &Path) -> Result<(), SignerError> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let permissions = metadata.permissions().mode();
        if permissions & 0o077 != 0 {
            eprintln!(
                "Warning: Private key '{}' is accessible by others (mode {:o}).",
                path.display(),
                permissions
            );
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_key_permissions(_path: &Path) -> Result<(), SignerError> {
        Ok(())
    }
}

/// Processor for signing and packaging ZIP/APK/JAR archives.
pub struct ArtifactProcessor;

/// Contains computed digests and nested archive sources.
pub struct NestedDigests {
    pub digests: BTreeMap<String, String>,
    pub nested_sources: BTreeMap<String, Vec<u8>>,
}

impl ArtifactProcessor {
    pub fn compute_manifest_digests(path: &Path) -> Result<BTreeMap<String, String>, SignerError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(BufReader::new(file))?;
        let mut digests = BTreeMap::new();

        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i)?;
            let name = zip_file.name().to_string();
            // Skip directory entries and existing metadata
            if !name.ends_with('/') && !name.starts_with("META-INF/") {
                digests.insert(name, CryptoEngine::compute_stream_sha1(&mut zip_file)?);
            }
        }
        Ok(digests)
    }

    pub fn compute_digests_prepare_nested(
        path: &Path,
        keys: &KeyChain,
    ) -> Result<NestedDigests, SignerError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(BufReader::new(file))?;
        let mut digests = BTreeMap::new();
        let mut nested_sources: BTreeMap<String, Vec<u8>> = BTreeMap::new();

        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i)?;
            let name = zip_file.name().to_string();
            if name.ends_with('/') || name.starts_with("META-INF/") {
                continue;
            }
            if name.ends_with(".zip") || name.ends_with(".jar") || name.ends_with(".apk") {
                let tmpdir = tempdir()?;
                let nested_src = tmpdir.path().join("nested-src.zip");
                let nested_signed = tmpdir.path().join("nested-signed.zip");

                {
                    let mut out = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&nested_src)?;
                    let mut buf = [0u8; BUFFER_SIZE];
                    loop {
                        let n = zip_file.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        out.write_all(&buf[..n])?;
                    }
                }

                let nested_digests = Self::compute_manifest_digests(&nested_src)?;
                Self::write_signed_zip(&nested_src, &nested_signed, keys, &nested_digests)?;

                // Read signed nested archive into memory for embedding
                let nested_bytes = fs::read(&nested_signed)?;
                let digest = CryptoEngine::compute_sha1(&nested_bytes);
                digests.insert(name.clone(), digest);
                nested_sources.insert(name, nested_bytes);
            } else {
                let digest = CryptoEngine::compute_stream_sha1(&mut zip_file)?;
                digests.insert(name, digest);
            }
        }

        Ok(NestedDigests { digests, nested_sources })
    }

    pub fn write_signed_zip(
        input: &Path,
        output: &Path,
        keys: &KeyChain,
        digests: &BTreeMap<String, String>,
    ) -> Result<(), SignerError> {
        let timestamp = keys.get_reproducible_timestamp();
        ui::log_info(&format!(
            "Applying certificate creation timestamp to all entries: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            timestamp.year(), timestamp.month(), timestamp.day(), timestamp.hour(), timestamp.minute(), timestamp.second()
        ));

        let out_file = OpenOptions::new().create(true).write(true).truncate(true).open(output)?;
        let mut writer = ZipWriter::new(BufWriter::new(out_file));

        // 1. Generate Manifest
        let manifest_bytes = Self::gen_manifest(digests);

        // 2. Generate Signature File (SF)
        let sf_bytes = Self::gen_sf(&manifest_bytes, digests);

        // 3. Generate RSA Signature Block
        let rsa_bytes = Self::gen_rsa(keys, &sf_bytes)?;

        // 4. Write Metadata Entries (Must be first in the ZIP)
        Self::write_entry(&mut writer, MANIFEST_NAME, &manifest_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa_bytes, timestamp)?;

        // 5. Copy Original Files
        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;
        let mut buf = [0u8; BUFFER_SIZE];

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();

            // Skip existing signature files
            if !name.starts_with("META-INF/")
                && !name.ends_with("MANIFEST.MF")
                && !name.ends_with(".SF")
                && !name.ends_with(".RSA")
            {
                let options = FileOptions::<()>::default()
                    .compression_method(file.compression())
                    .last_modified_time(timestamp)
                    .unix_permissions(file.unix_mode().unwrap_or(0o644));

                writer.start_file(&name, options)?;
                // If nested archive, process recursively
                if name.ends_with(".zip") || name.ends_with(".jar") || name.ends_with(".apk") {
                    ui::log_info(&format!(
                        "Found nested archive: `{}` (signing recursively)",
                        name
                    ));
                    let tmpdir = tempdir()?;
                    let nested_src = tmpdir.path().join("nested-src.zip");
                    let nested_signed = tmpdir.path().join("nested-signed.zip");

                    // Dump current file content to temp nested_src
                    {
                        let mut out = OpenOptions::new()
                            .create(true)
                            .write(true)
                            .truncate(true)
                            .open(&nested_src)?;
                        loop {
                            let n = file.read(&mut buf)?;
                            if n == 0 {
                                break;
                            }
                            out.write_all(&buf[..n])?;
                        }
                    }

                    // Compute digests for nested, then sign it
                    let nested_digests = Self::compute_manifest_digests(&nested_src)?;
                    Self::write_signed_zip(&nested_src, &nested_signed, keys, &nested_digests)?;

                    // Apply filesystem mtime to nested_signed
                    let ft =
                        FileTime::from_unix_time(Self::zip_datetime_to_unix(&timestamp) as i64, 0);
                    set_file_times(&nested_signed, ft, ft)?;
                    ui::log_info(&format!(
                        "Set filesystem mtime on nested archive: `{}`",
                        nested_signed.display()
                    ));

                    // Stream nested_signed back into the parent writer
                    let mut nested_file = BufReader::new(File::open(&nested_signed)?);
                    loop {
                        let n = nested_file.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        writer.write_all(&buf[..n])?;
                    }
                } else {
                    loop {
                        let n = file.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        writer.write_all(&buf[..n])?;
                    }
                }
            }
        }
        writer.finish()?;
        // Apply filesystem mtime to output zip: current system time
        let now = std::time::SystemTime::now();
        let ft = FileTime::from_system_time(now);
        set_file_times(output, ft, ft)?;
        ui::log_info(&format!(
            "Set filesystem mtime (current) on output archive: `{}`",
            output.display()
        ));
        // Basic integrity check: open the resulting zip and iterate entries to ensure readability
        Self::verify_zip_integrity(output)?;
        Ok(())
    }

    pub fn write_signed_zip_with_sources(
        input: &Path,
        output: &Path,
        keys: &KeyChain,
        digests: &BTreeMap<String, String>,
        nested_sources: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), SignerError> {
        let timestamp = keys.get_reproducible_timestamp();
        ui::log_info(&format!(
            "Applying certificate creation timestamp to all entries: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            timestamp.year(), timestamp.month(), timestamp.day(), timestamp.hour(), timestamp.minute(), timestamp.second()
        ));

        let out_file = OpenOptions::new().create(true).write(true).truncate(true).open(output)?;
        let mut writer = ZipWriter::new(BufWriter::new(out_file));

        let manifest_bytes = Self::gen_manifest(digests);
        let sf_bytes = Self::gen_sf(&manifest_bytes, digests);
        let rsa_bytes = Self::gen_rsa(keys, &sf_bytes)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &manifest_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa_bytes, timestamp)?;

        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;
        let mut buf = [0u8; BUFFER_SIZE];
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();
            if !name.starts_with("META-INF/")
                && !name.ends_with("MANIFEST.MF")
                && !name.ends_with(".SF")
                && !name.ends_with(".RSA")
            {
                let options = FileOptions::<()>::default()
                    .compression_method(file.compression())
                    .last_modified_time(timestamp)
                    .unix_permissions(file.unix_mode().unwrap_or(0o644));
                writer.start_file(&name, options)?;

                if let Some(nested_bytes) = nested_sources.get(&name) {
                    ui::log_info(&format!("Embedding signed nested archive: `{}`", name));
                    writer.write_all(nested_bytes)?;
                } else {
                    loop {
                        let n = file.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        writer.write_all(&buf[..n])?;
                    }
                }
            }
        }

        writer.finish()?;
        let now = std::time::SystemTime::now();
        let ft = FileTime::from_system_time(now);
        set_file_times(output, ft, ft)?;
        ui::log_info(&format!(
            "Set filesystem mtime (current) on output archive: `{}`",
            output.display()
        ));
        Self::verify_zip_integrity(output)?;
        Ok(())
    }

    fn write_entry(
        w: &mut ZipWriter<BufWriter<File>>,
        n: &str,
        d: &[u8],
        t: DateTime,
    ) -> Result<(), SignerError> {
        let options = FileOptions::<()>::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(t);
        w.start_file(n, options)?;
        w.write_all(d)?;
        Ok(())
    }

    fn write_manifest_line(out: &mut Vec<u8>, key: &str, value: &str) {
        let line = format!("{}: {}", key, value).into_bytes();

        // Max line length in JAR manifest is 72 bytes (utf8).
        // Continuation lines must start with a space.
        let mut cursor = 0;
        let len = line.len();

        while cursor < len {
            let remaining = len - cursor;
            // First line limit is 72. Subsequent lines limit is 71 (72 - 1 space).
            let limit = if cursor == 0 { 72 } else { 71 };
            let chunk_size = std::cmp::min(remaining, limit);

            if cursor > 0 {
                out.push(b' '); // Continuation prefix
            }

            out.extend_from_slice(&line[cursor..cursor + chunk_size]);
            out.extend_from_slice(b"\r\n");

            cursor += chunk_size;
        }
    }

    fn create_manifest_entry(name: &str, hash: &str) -> Vec<u8> {
        let mut entry = Vec::new();
        Self::write_manifest_line(&mut entry, "Name", name);
        Self::write_manifest_line(&mut entry, "SHA1-Digest", hash);
        entry.extend_from_slice(b"\r\n"); // Section delimiter
        entry
    }

    fn gen_manifest(digests: &BTreeMap<String, String>) -> Vec<u8> {
        let mut out = Vec::new();

        // Main Attributes
        out.extend_from_slice(b"Manifest-Version: 1.0\r\n");
        Self::write_manifest_line(&mut out, "Created-By", APP_NAME);
        out.extend_from_slice(b"\r\n"); // End of Main Attributes

        // Individual Entries
        for (name, hash) in digests {
            out.extend(Self::create_manifest_entry(name, hash));
        }
        out
    }

    fn gen_sf(manifest_bytes: &[u8], digests: &BTreeMap<String, String>) -> Vec<u8> {
        let mut out = Vec::new();

        // Main Attributes
        out.extend_from_slice(b"Signature-Version: 1.0\r\n");
        Self::write_manifest_line(&mut out, "Created-By", APP_NAME);

        // The SHA1-Digest-Manifest is the hash of the ENTIRE manifest file
        let manifest_hash = CryptoEngine::compute_sha1(manifest_bytes);
        Self::write_manifest_line(&mut out, "SHA1-Digest-Manifest", &manifest_hash);
        out.extend_from_slice(b"\r\n"); // End of Main Attributes

        // Individual Entries
        for name in digests.keys() {
            if let Some(file_hash) = digests.get(name) {
                let manifest_entry_bytes = Self::create_manifest_entry(name, file_hash);
                let manifest_entry_hash = CryptoEngine::compute_sha1(&manifest_entry_bytes);

                Self::write_manifest_line(&mut out, "Name", name);
                Self::write_manifest_line(&mut out, "SHA1-Digest", &manifest_entry_hash);
                out.extend_from_slice(b"\r\n");
            }
        }
        out
    }

    fn gen_rsa(keys: &KeyChain, sf: &[u8]) -> Result<Vec<u8>, SignerError> {
        let key_pair =
            keys.private_key.as_ref().ok_or(SignerError::Config("Private Key Missing".into()))?;

        let mut signature = vec![0u8; key_pair.public().modulus_len()];

        let rng = SystemRandom::new();
        // Sign the raw SF bytes; verifier computes the digest internally for RSA_PKCS1_SHA256
        key_pair.sign(RSA_SIGNATURE_SCHEME, &rng, sf, &mut signature)?;

        Ok(signature)
    }

    fn verify_zip_integrity(path: &Path) -> Result<(), SignerError> {
        let mut archive = ZipArchive::new(BufReader::new(File::open(path)?))?;
        let mut buf = [0u8; BUFFER_SIZE];
        for i in 0..archive.len() {
            let mut f = archive.by_index(i)?;
            let mut hasher = Crc32::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let stored = f.crc32();
            let computed = hasher.clone().finalize();
            if stored != computed {
                return Err(SignerError::Validation(format!(
                    "CRC mismatch for `{}`: stored={:#010x}, computed={:#010x}",
                    f.name(),
                    stored,
                    computed
                )));
            }
        }
        Ok(())
    }

    fn zip_datetime_to_unix(dt: &DateTime) -> u64 {
        use chrono::NaiveDate;

        let year = dt.year() as i32;
        // DOS years are 1980+. Clamp to 1980 to avoid issues.
        let year = if year < 1980 { 1980 } else { year };

        let nd = NaiveDate::from_ymd_opt(year, dt.month() as u32, dt.day() as u32)
            .unwrap_or(NaiveDate::from_ymd_opt(1980, 1, 1).unwrap());

        let ndt = nd
            .and_hms_opt(dt.hour() as u32, dt.minute() as u32, dt.second() as u32)
            .unwrap_or_default();

        // Treat as UTC for stability in mtime setting
        ndt.and_utc().timestamp().max(0) as u64
    }
}

impl KeyChain {
    fn asn1_to_zip_datetime(asn1: ASN1Time) -> DateTime {
        // Convert to OffsetDateTime using x509-parser's logic
        // This returns the certificate's timestamp in UTC
        let dt = asn1.to_datetime();
        
        // Extract components directly from the UTC timestamp
        // This ensures we use the exact time from the certificate without timezone shifts
        let year = dt.year() as u16;
        let month = dt.month() as u8;
        let day = dt.day();
        let hour = dt.hour();
        let minute = dt.minute();
        let second = dt.second();

        DateTime::from_date_and_time(year, month, day, hour, minute, second)
            .unwrap_or_else(|_| {
                ui::log_error(&format!(
                    "Failed to create DateTime from certificate date: {}-{:02}-{:02} {:02}:{:02}:{:02}. Fallback to 1980.",
                    year, month, day, hour, minute, second
                ));
                DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap()
            })
    }
}
