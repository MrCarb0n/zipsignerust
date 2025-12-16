/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

//! ZIP archive processing and signing functionality.
//! Handles manifest generation, nested archive signing, and ZIP integrity verification.

use crate::{
    crypto::CryptoEngine, error::SignerError, keys::KeyChain, ui::Ui, APP_NAME, BUFFER_SIZE,
    CERT_RSA_NAME, CERT_SF_NAME, MANIFEST_NAME,
};
use crc32fast::Hasher as Crc32;
use filetime::{set_file_times, FileTime};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};
use tempfile::tempdir;
use zip::{
    write::{FileOptions, ZipWriter},
    CompressionMethod, DateTime, ZipArchive,
};

// Thread-local buffer for I/O operations to reduce allocations
thread_local! {
    static PROCESSING_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0u8; BUFFER_SIZE]);
}

/// Container for digests and nested file data during signing process.
#[derive(Debug)]
pub struct NestedDigests {
    /// Map of file paths to their SHA1 digests
    pub digests: BTreeMap<String, String>,
    /// Map of nested archive paths to their processed content
    pub nested_files: BTreeMap<String, Vec<u8>>,
}

/// Core processor for ZIP signing operations including manifest generation,
/// nested archive handling, and integrity verification.
pub struct ArtifactProcessor;

impl ArtifactProcessor {
    /// Calculate hashes for all files in archive
    pub fn compute_manifest_digests(
        path: &Path,
        ui: &Ui,
    ) -> Result<BTreeMap<String, String>, SignerError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(BufReader::new(file))?;
        let len = archive.len();

        // Show progress for large archives
        if ui.verbose {
            let non_signature_count = (0..len)
                .filter_map(|i| {
                    archive.by_index(i).ok().and_then(|f| {
                        let name = f.name();
                        if !name.ends_with('/')
                            && (!name.starts_with("META-INF/")
                                || !(name == MANIFEST_NAME
                                    || name == CERT_SF_NAME
                                    || name == CERT_RSA_NAME
                                    || name.ends_with("/MANIFEST.MF")
                                    || name.ends_with(".SF")
                                    || name.ends_with(".RSA")))
                        {
                            Some(name.to_string())
                        } else {
                            None
                        }
                    })
                })
                .count();

            if non_signature_count > 10 {
                // Only show progress bar if there are many files to process
                ui.show_progress_bar(non_signature_count as u64, "Computing digests");
            }
        }

        // Single archive pass to collect digests
        let mut digests = BTreeMap::new();

        for i in 0..len {
            let mut zip_file = archive.by_index(i)?;
            let name = zip_file.name().to_string();

            if !name.ends_with('/') {
                // Only include non-signature META-INF files and other regular files
                if name.starts_with("META-INF/") {
                    // Skip signature-related files that get regenerated
                    if name == MANIFEST_NAME
                        || name == CERT_SF_NAME
                        || name == CERT_RSA_NAME
                        || name.ends_with("/MANIFEST.MF")
                        || name.ends_with(".SF")
                        || name.ends_with(".RSA")
                    {
                        continue; // Skip this file as it will be regenerated during signing
                    }
                    // Otherwise, include non-signature META-INF files
                }

                let digest = CryptoEngine::compute_stream_sha1(&mut zip_file)?;
                digests.insert(name.clone(), digest);

                // Update progress bar if it exists
                if ui.has_progress_bar() {
                    ui.update_progress(digests.len() as u64);
                }
            }
        }

        // Finish progress bar
        if ui.has_progress_bar() {
            ui.finish_progress();
        }

        Ok(digests)
    }

    pub fn compute_digests_prepare_nested(
        path: &Path,
        keys: &KeyChain,
        ui: &Ui,
    ) -> Result<NestedDigests, SignerError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(BufReader::new(file))?;
        let mut digests = BTreeMap::new();
        let mut nested_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i)?;
            let name = zip_file.name().to_string();

            // Only skip signature-related META-INF files during digest computation
            if name.ends_with('/') {
                continue;
            }

            if name.starts_with("META-INF/") {
                // Skip only the signature files during digest computation since they'll be replaced
                if name == MANIFEST_NAME
                    || name == CERT_SF_NAME
                    || name == CERT_RSA_NAME
                    || name.ends_with("/MANIFEST.MF")
                    || name.ends_with(".SF")
                    || name.ends_with(".RSA")
                {
                    continue; // Skip this file as it will be regenerated during signing
                }
                // Otherwise, treat non-signature META-INF files like regular files for digest computation
            }

            if name.ends_with(".zip") || name.ends_with(".jar") || name.ends_with(".apk") {
                // Extract nested archive to temp file (using a more efficient approach)
                let tmpdir = tempdir()?;
                let nested_src = tmpdir.path().join("nested-src.zip");
                let nested_signed = tmpdir.path().join("nested-signed.zip");

                {
                    let mut out = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&nested_src)?;

                    // Use buffered copy for efficiency
                    std::io::copy(&mut zip_file, &mut out)?;
                }

                let nested_digests = Self::compute_manifest_digests(&nested_src, ui)?;
                Self::write_signed_zip(&nested_src, &nested_signed, keys, &nested_digests, ui)?;

                let nested_bytes = fs::read(&nested_signed)?;
                let digest = CryptoEngine::compute_sha1(&nested_bytes);
                digests.insert(name.clone(), digest);
                nested_files.insert(name, nested_bytes);
            } else {
                let digest = CryptoEngine::compute_stream_sha1(&mut zip_file)?;
                digests.insert(name, digest);
            }
        }

        Ok(NestedDigests {
            digests,
            nested_files,
        })
    }

    pub fn write_signed_zip(
        input: &Path,
        output: &Path,
        keys: &KeyChain,
        digests: &BTreeMap<String, String>,
        ui: &Ui,
    ) -> Result<(), SignerError> {
        let timestamp = keys.get_reproducible_timestamp();

        // Create output file with buffered writer for better performance
        let out_file = File::create(output)?;
        let buf_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);
        let mut writer = ZipWriter::new(buf_writer);

        let manifest_bytes = Self::gen_manifest(digests);
        let sf_bytes = Self::gen_sf(&manifest_bytes, digests);
        let rsa_bytes = Self::gen_rsa(keys, &sf_bytes)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &manifest_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa_bytes, timestamp)?;

        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;
        let total_files = archive.len();

        // Show progress for writing files
        if ui.verbose {
            ui.show_progress_bar(total_files as u64, "Writing files");
        }

        PROCESSING_BUFFER.with(|local_buf| {
            let mut buf = local_buf.borrow_mut();
            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;
                let name = file.name().to_string();

                if name.starts_with("META-INF/") {
                    if name == MANIFEST_NAME
                        || name == CERT_SF_NAME
                        || name == CERT_RSA_NAME
                        || name.ends_with("/MANIFEST.MF")
                        || name.ends_with(".SF")
                        || name.ends_with(".RSA")
                    {
                        continue;
                    }
                }

                let options = FileOptions::<()>::default()
                    .compression_method(file.compression())
                    .last_modified_time(timestamp)
                    .unix_permissions(file.unix_mode().unwrap_or(0o644))
                    .with_alignment(4);

                writer.start_file(&name, options)?;
                if name.ends_with(".zip") || name.ends_with(".jar") || name.ends_with(".apk") {
                    ui.info(&format!("Signing nested archive: {}", name));
                    let tmpdir = tempdir()?;
                    let nested_src = tmpdir.path().join("nested-src.zip");
                    let nested_signed = tmpdir.path().join("nested-signed.zip");

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

                    let nested_digests = Self::compute_manifest_digests(&nested_src, ui)?;
                    Self::write_signed_zip(&nested_src, &nested_signed, keys, &nested_digests, ui)?;

                    // Set filesystem timestamp
                    let ft = FileTime::from_system_time(std::time::SystemTime::now());
                    set_file_times(&nested_signed, ft, ft)?;
                    ui.verbose(&format!(
                        "mtime set on nested archive: {}",
                        nested_signed.display()
                    ));

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

                // Update progress - only update if ui has a progress bar
                if ui.verbose && ui.has_progress_bar() {
                    ui.update_progress((i + 1) as u64);
                }
            }
            Ok::<(), SignerError>(())
        })?;

        // Finish progress
        if ui.verbose && ui.has_progress_bar() {
            ui.finish_progress();
        }

        writer.finish()?;
        let now = std::time::SystemTime::now();
        let ft = FileTime::from_system_time(now);
        set_file_times(output, ft, ft)?;
        ui.verbose(&format!("mtime set on output: {}", output.display()));
        Self::verify_zip_integrity(output)?;
        Ok(())
    }

    pub fn write_signed_zip_with_sources(
        input: &Path,
        output: &Path,
        keys: &KeyChain,
        digests: &BTreeMap<String, String>,
        nested_files: &BTreeMap<String, Vec<u8>>,
        ui: &Ui,
    ) -> Result<(), SignerError> {
        let timestamp = keys.get_reproducible_timestamp();

        // Create output file with buffered writer for better performance
        let out_file = File::create(output)?;
        let buf_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);
        let mut writer = ZipWriter::new(buf_writer);

        let manifest_bytes = Self::gen_manifest(digests);
        let sf_bytes = Self::gen_sf(&manifest_bytes, digests);
        let rsa_bytes = Self::gen_rsa(keys, &sf_bytes)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &manifest_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa_bytes, timestamp)?;

        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;

        // Use thread-local buffer to avoid allocations in the hot path
        PROCESSING_BUFFER.with(|local_buf| {
            let mut buf = local_buf.borrow_mut();
            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;
                let name = file.name().to_string();

                if name.starts_with("META-INF/") {
                    if name == MANIFEST_NAME
                        || name == CERT_SF_NAME
                        || name == CERT_RSA_NAME
                        || name.ends_with("/MANIFEST.MF")
                        || name.ends_with(".SF")
                        || name.ends_with(".RSA")
                    {
                        continue;
                    }
                }

                let options = FileOptions::<()>::default()
                    .compression_method(file.compression())
                    .last_modified_time(timestamp)
                    .unix_permissions(file.unix_mode().unwrap_or(0o644))
                    .with_alignment(4);

                writer.start_file(&name, options)?;

                if let Some(nested_bytes) = nested_files.get(&name) {
                    ui.info(&format!("Embedding signed nested archive: {}", name));
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
            Ok::<(), SignerError>(())
        })?;

        writer.finish()?;
        let now = std::time::SystemTime::now();
        let ft = FileTime::from_system_time(now);
        set_file_times(output, ft, ft)?;
        ui.verbose(&format!("mtime set on output: {}", output.display()));
        Self::verify_zip_integrity(output)?;
        Ok(())
    }

    fn get_timestamp_for_signing(
        keys: &KeyChain,
        timestamp_str: &Option<String>,
        _ui: &Ui,
    ) -> Result<DateTime, SignerError> {
        // If no custom timestamp is provided, use the reproducible timestamp from keys
        if timestamp_str.is_none() {
            let timestamp = keys.get_reproducible_timestamp();
            return Ok(timestamp);
        }

        // Parse the custom timestamp
        let ts_str = timestamp_str.as_ref().unwrap();
        if ts_str == "reproducible" {
            let timestamp = keys.get_reproducible_timestamp();
            return Ok(timestamp);
        }

        // Parse timestamp in format "YYYY-MM-DD HH:MM:SS"
        let parts: Vec<&str> = ts_str.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(SignerError::Config(
                "Invalid timestamp format. Use 'YYYY-MM-DD HH:MM:SS'".to_string(),
            ));
        }

        let date_parts: Vec<&str> = parts[0].split('-').collect();
        let time_parts: Vec<&str> = parts[1].split(':').collect();

        if date_parts.len() != 3 || time_parts.len() != 3 {
            return Err(SignerError::Config(
                "Invalid timestamp format. Use 'YYYY-MM-DD HH:MM:SS'".to_string(),
            ));
        }

        // Helper for parsing with error message
        let parse_part = |part: &str, desc: &str| {
            part.parse::<u16>()
                .map_err(|_| SignerError::Config(format!("Invalid {} in timestamp", desc)))
        };

        let year = parse_part(date_parts[0], "year")?;
        let month = parse_part(date_parts[1], "month")? as u8;
        let day = parse_part(date_parts[2], "day")? as u8;
        let hour = parse_part(time_parts[0], "hour")? as u8;
        let minute = parse_part(time_parts[1], "minute")? as u8;
        let second = parse_part(time_parts[2], "second")? as u8;

        // Validate ranges
        let (month_ok, day_ok, hour_ok, minute_ok, second_ok) = (
            (1..=12).contains(&month),
            (1..=31).contains(&day),
            (0..=23).contains(&hour),
            (0..=59).contains(&minute),
            (0..=59).contains(&second),
        );

        if !month_ok {
            return Err(SignerError::Config(
                "Month must be between 1 and 12".to_string(),
            ));
        } else if !day_ok {
            return Err(SignerError::Config(
                "Day must be between 1 and 31".to_string(),
            ));
        } else if !hour_ok {
            return Err(SignerError::Config(
                "Hour must be between 0 and 23".to_string(),
            ));
        } else if !minute_ok {
            return Err(SignerError::Config(
                "Minute must be between 0 and 59".to_string(),
            ));
        } else if !second_ok {
            return Err(SignerError::Config(
                "Second must be between 0 and 59".to_string(),
            ));
        }

        // Create the DateTime object
        let timestamp = DateTime::from_date_and_time(year, month, day, hour, minute, second)
            .map_err(|e| SignerError::Config(format!("Invalid date/time: {}", e)))?;

        Ok(timestamp)
    }

    fn write_entry(
        w: &mut ZipWriter<BufWriter<File>>,
        n: &str,
        d: &[u8],
        t: DateTime,
    ) -> Result<(), SignerError> {
        let options = FileOptions::<()>::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(t)
            .with_alignment(4);
        w.start_file(n, options)?;
        w.write_all(d)?;
        Ok(())
    }

    fn write_manifest_line(out: &mut Vec<u8>, key: &str, value: &str) {
        // Check if this field should not be wrapped according to JAR specification
        // This ensures Name fields, digest values, and other critical fields stay on one continuous line
        if Self::is_non_wrapping_field(key) {
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

    /// Check if the field should not be line-wrapped according to JAR specification
    /// This ensures that headers like Name, SHA1-Digest, etc. stay on one continuous line
    fn is_non_wrapping_field(key: &str) -> bool {
        // Name field should not wrap as it contains file paths
        key == "Name" ||
        // All digest fields including SHA1-Digest, SHA-256-Digest, MD5-Digest, etc.
        key.contains("-Digest") || key.contains("_Digest") ||
        // Also handle the specific manifest digest fields
        key == "SHA1-Digest-Manifest" || key == "SHA-256-Digest-Manifest" ||
        key == "MD5-Digest-Manifest"
    }

    fn create_manifest_entry(name: &str, hash: &str) -> Vec<u8> {
        // Pre-calculate approximate size to reduce reallocations
        let estimated_size = name.len() + hash.len() + 50; // Estimate for formatting overhead
        let mut entry = Vec::with_capacity(estimated_size);
        Self::write_manifest_line(&mut entry, "Name", name);
        Self::write_manifest_line(&mut entry, "SHA1-Digest", hash);
        entry.extend_from_slice(b"\r\n");
        entry
    }

    fn gen_manifest(digests: &BTreeMap<String, String>) -> Vec<u8> {
        // Pre-calculate approximate size to reduce reallocations
        let estimated_size = 50 + // Initial manifest headers
            digests.len() * 100 + // Approximate size per entry
            digests.values().map(|h| h.len()).sum::<usize>();

        let mut out = Vec::with_capacity(estimated_size);
        out.extend_from_slice(b"Manifest-Version: 1.0\r\n");
        Self::write_manifest_line(&mut out, "Created-By", APP_NAME);
        out.extend_from_slice(b"\r\n");
        for (name, hash) in digests {
            out.extend(Self::create_manifest_entry(name, hash));
        }
        out
    }

    fn gen_sf(manifest_bytes: &[u8], digests: &BTreeMap<String, String>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"Signature-Version: 1.0\r\n");
        Self::write_manifest_line(&mut out, "Created-By", APP_NAME);
        let manifest_hash = CryptoEngine::compute_sha1(manifest_bytes);
        Self::write_manifest_line(&mut out, "SHA1-Digest-Manifest", &manifest_hash);
        out.extend_from_slice(b"\r\n");
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
        let key_pair = keys.private_key.as_ref().ok_or(SignerError::Config(
            "Private key missing for signing".into(),
        ))?;
        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        let rng = ring::rand::SystemRandom::new();
        let rsa_signature_scheme = crate::keys::RSA_SIGNATURE_SCHEME;
        key_pair.sign(rsa_signature_scheme, &rng, sf, &mut signature)?;
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
            let (stored, computed) = (f.crc32(), hasher.finalize());
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

    pub fn write_signed_zip_with_custom_timestamp(
        input: &Path,
        output: &Path,
        keys: &KeyChain,
        digests: &BTreeMap<String, String>,
        nested_files: &BTreeMap<String, Vec<u8>>,
        ui: &Ui,
        timestamp_str: &Option<String>,
    ) -> Result<(), SignerError> {
        let timestamp = Self::get_timestamp_for_signing(keys, timestamp_str, ui)?;

        // Create output file with buffered writer for better performance
        let out_file = File::create(output)?;
        let buf_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);
        let mut writer = ZipWriter::new(buf_writer);

        let manifest_bytes = Self::gen_manifest(digests);
        let sf_bytes = Self::gen_sf(&manifest_bytes, digests);
        let rsa_bytes = Self::gen_rsa(keys, &sf_bytes)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &manifest_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf_bytes, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa_bytes, timestamp)?;

        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;

        // Use thread-local buffer to avoid allocations in the hot path
        PROCESSING_BUFFER.with(|local_buf| {
            let mut buf = local_buf.borrow_mut();
            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;
                let name = file.name().to_string();

                if name.starts_with("META-INF/") {
                    if name == MANIFEST_NAME
                        || name == CERT_SF_NAME
                        || name == CERT_RSA_NAME
                        || name.ends_with("/MANIFEST.MF")
                        || name.ends_with(".SF")
                        || name.ends_with(".RSA")
                    {
                        continue;
                    }
                }

                let options = FileOptions::<()>::default()
                    .compression_method(file.compression())
                    .last_modified_time(timestamp)
                    .unix_permissions(file.unix_mode().unwrap_or(0o644))
                    .with_alignment(4);

                writer.start_file(&name, options)?;

                if let Some(nested_bytes) = nested_files.get(&name) {
                    ui.info(&format!("Embedding signed nested archive: {}", name));
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
            Ok::<(), SignerError>(())
        })?;

        writer.finish()?;
        let now = std::time::SystemTime::now();
        let ft = FileTime::from_system_time(now);
        set_file_times(output, ft, ft)?;
        ui.verbose(&format!("mtime set on output: {}", output.display()));
        Self::verify_zip_integrity(output)?;
        Ok(())
    }
}
