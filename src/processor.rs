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
use rayon::prelude::*;
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
        _ui: &Ui,
    ) -> Result<BTreeMap<String, String>, SignerError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(BufReader::new(file))?;
        let len = archive.len();

        // Collect file metadata first to avoid locking archive during parallel processing
        let mut files_to_process = Vec::with_capacity(len);
        for i in 0..len {
            let zip_file = archive.by_index(i)?;
            let name = zip_file.name().to_string();
            if !name.ends_with('/') && !name.starts_with("META-INF/") {
                files_to_process.push(name);
            }
        }

        // Process files in parallel with individual archive handles
        let digests: Result<Vec<(String, String)>, _> = files_to_process
            .into_par_iter()
            .map(|name| {
                let file = File::open(path)?;
                let mut local_archive = ZipArchive::new(BufReader::new(file))?;

                let mut zip_file = local_archive.by_name(&name)?;
                let digest = CryptoEngine::compute_stream_sha1(&mut zip_file)?;
                Ok((name, digest))
            })
            .collect();

        digests.map(|results| results.into_iter().collect())
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
        ui.verbose(&format!(
            "Timestamp used: {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            timestamp.year(),
            timestamp.month(),
            timestamp.day(),
            timestamp.hour(),
            timestamp.minute(),
            timestamp.second()
        ));

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

        // Use thread-local buffer to avoid allocations in the hot path
        PROCESSING_BUFFER.with(|local_buf| {
            let mut buf = local_buf.borrow_mut();
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
                        Self::write_signed_zip(
                            &nested_src,
                            &nested_signed,
                            keys,
                            &nested_digests,
                            ui,
                        )?;

                        // Use UTC logic for filesystem timestamp
                        let ft = FileTime::from_unix_time(
                            Self::zip_datetime_to_unix(&timestamp) as i64,
                            0,
                        );
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
        ui.verbose(&format!(
            "Timestamp used: {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            timestamp.year(),
            timestamp.month(),
            timestamp.day(),
            timestamp.hour(),
            timestamp.minute(),
            timestamp.second()
        ));

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
                if !name.starts_with("META-INF/")
                    && !name.ends_with("MANIFEST.MF")
                    && !name.ends_with(".SF")
                    && !name.ends_with(".RSA")
                {
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
        let year = if year < 1980 { 1980 } else { year };
        let nd = NaiveDate::from_ymd_opt(year, dt.month() as u32, dt.day() as u32)
            .unwrap_or(NaiveDate::from_ymd_opt(1980, 1, 1).unwrap());
        let ndt = nd
            .and_hms_opt(dt.hour() as u32, dt.minute() as u32, dt.second() as u32)
            .unwrap_or_default();

        // Ensure strictly UTC conversion
        ndt.and_utc().timestamp().max(0) as u64
    }
}
