/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::{
    crypto::CryptoEngine, error::SignerError, keys::KeyChain, ui::Ui, APP_NAME, BUFFER_SIZE,
    CERT_PUBLIC_KEY_NAME, CERT_RSA_NAME, CERT_SF_NAME, MANIFEST_NAME,
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

thread_local! { static PB: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0u8; BUFFER_SIZE]); }

#[derive(Debug)]
pub struct NestedDigests {
    pub digests: BTreeMap<String, String>,
    pub nested_files: BTreeMap<String, Vec<u8>>,
}

pub struct ArtifactProcessor;

impl ArtifactProcessor {
    pub fn compute_manifest_digests(
        path: &Path,
        ui: &Ui,
    ) -> Result<BTreeMap<String, String>, SignerError> {
        let mut archive = ZipArchive::new(BufReader::new(File::open(path)?))?;
        let len = archive.len();
        ui.verbose(&format!("Digests: {} entries in {}", len, path.display()));

        let mut stats = (0u64, 0u64); // (total_size, non_sig_count)
        for i in 0..len {
            if let Some(f) = archive.by_index(i).ok() {
                let name = f.name();
                if !name.ends_with('/') && !Self::is_sig_file(&name) {
                    stats.0 += f.size();
                    stats.1 += 1;
                }
            }
        }
        ui.verbose(&format!("Process: {} files ({} bytes)", stats.1, stats.0));

        if ui.verbose && stats.1 > 0 {
            if stats.0 > 10 * 1024 * 1024 {
                ui.show_detailed_progress_bar(stats.0, "Manifest digests", "bytes");
            } else if stats.1 > 10 {
                ui.show_progress_bar(stats.1, "Manifest digests");
            } else {
                ui.verbose("Skipping progress bar: <10 files");
            }
        }

        let (mut digests, mut pos) = (BTreeMap::new(), 0u64);
        for i in 0..len {
            let mut f = archive.by_index(i)?;
            let name = f.name().to_string();

            if !name.ends_with('/') && !Self::is_sig_file(&name) {
                ui.very_verbose(&format!("SHA1: {} ({} bytes)", name, f.size()));
                let digest =
                    CryptoEngine::compute_stream_sha1_with_ui(&mut f, Some(ui), Some(&name))?;
                digests.insert(name, digest);
                if ui.has_progress_bar() {
                    ui.update_progress(pos + f.size());
                    pos += f.size();
                }
            }
        }
        ui.verbose(&format!("Digests: {} files processed", digests.len()));
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
        let mut archive = ZipArchive::new(BufReader::new(File::open(path)?))?;
        let (mut digests, mut nested_files) = (BTreeMap::new(), BTreeMap::new());

        for i in 0..archive.len() {
            let mut f = archive.by_index(i)?;
            let name = f.name().to_string();

            if name.ends_with('/') || Self::is_sig_file(&name) {
                continue;
            }

            if name.ends_with(".zip") {
                ui.verbose(&format!("Nested: {}", name));
                let tmpdir = tempdir()?;
                ui.record_temp_file(tmpdir.path());
                let (src, signed) = (
                    tmpdir.path().join("nested-src.zip"),
                    tmpdir.path().join("nested-signed.zip"),
                );
                ui.record_temp_file(&src);
                ui.record_temp_file(&signed);

                ui.verbose(&format!("Tmp: {:?}", tmpdir.path()));
                ui.info(&format!("Dir: {:?}", tmpdir.path()));
                ui.verbose(&format!("Extr: {:?}", src));

                {
                    let mut out = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&src)?;
                    std::io::copy(&mut f, &mut out)?;
                    ui.verbose(&format!("Extr: {} -> {}", name, src.display()));
                }

                let nested_digests = Self::compute_manifest_digests(&src, ui)?;
                ui.verbose(&format!("Nested: {} entries", nested_digests.len()));

                Self::write_signed_zip(&src, &signed, keys, &nested_digests, ui)?;
                ui.verbose(&format!("Signed: {:?}", signed));

                let nested_bytes = fs::read(&signed)?;
                let digest = CryptoEngine::compute_sha1(&nested_bytes);
                digests.insert(name.clone(), digest.clone());
                nested_files.insert(name.clone(), nested_bytes);
                ui.verbose(&format!("Proc: {} -> SHA1: {}", name, &digest[..8]));
                ui.verbose(&format!("Cleanup: {:?}", tmpdir.path()));
            } else {
                let digest =
                    CryptoEngine::compute_stream_sha1_with_ui(&mut f, Some(ui), Some(&name))?;
                digests.insert(name.clone(), digest.clone());
                ui.very_verbose(&format!("Digest: {} -> SHA1: {}", name, &digest[..8]));
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
        let mut writer =
            ZipWriter::new(BufWriter::with_capacity(BUFFER_SIZE, File::create(output)?));
        let mf = Self::gen_manifest(digests);
        let sf = Self::gen_sf(&mf, digests);
        let rsa = Self::gen_rsa(keys, &sf)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &mf, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa, timestamp)?;

        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;
        let mut total_size = 0u64;
        for i in 0..archive.len() {
            let f = archive.by_index(i)?;
            if !f.name().ends_with('/') && !Self::is_sig_file(f.name()) {
                total_size += f.size();
            }
        }

        if ui.verbose {
            if total_size > 10 * 1024 * 1024 {
                ui.show_detailed_progress_bar(total_size, "Processing", "bytes");
            } else {
                ui.show_progress_bar(archive.len() as u64, "Writing files");
            }
        }

        PB.with(|local_buf| {
            let mut buf = local_buf.borrow_mut();
            let mut pos = 0u64;
            for i in 0..archive.len() {
                let mut f = archive.by_index(i)?;
                let name = f.name().to_string();

                if Self::is_sig_file(&name) {
                    continue;
                }

                writer.start_file(
                    &name,
                    FileOptions::<()>::default()
                        .compression_method(f.compression())
                        .last_modified_time(timestamp)
                        .unix_permissions(f.unix_mode().unwrap_or(0o644))
                        .with_alignment(4),
                )?;

                if name.ends_with(".zip") {
                    ui.info(&format!("Nested: {}", name));
                    let tmpdir = tempdir()?;
                    ui.record_temp_file(tmpdir.path());
                    let (src, signed) = (
                        tmpdir.path().join("nested-src.zip"),
                        tmpdir.path().join("nested-signed.zip"),
                    );
                    ui.record_temp_file(&src);
                    ui.record_temp_file(&signed);

                    ui.verbose(&format!("Tmp dir: {:?}", tmpdir.path()));
                    if ui.verbose {
                        ui.info(&format!("Dir: {:?}", tmpdir.path()));
                    }
                    ui.verbose(&format!("Extr: {:?}", src));

                    let mut total_written = 0u64;
                    {
                        let mut out = OpenOptions::new()
                            .create(true)
                            .write(true)
                            .truncate(true)
                            .open(&src)?;
                        loop {
                            let n = f.read(&mut buf)?;
                            if n == 0 {
                                break;
                            }
                            out.write_all(&buf[..n])?;
                            total_written += n as u64;
                            if ui.has_progress_bar() {
                                ui.update_progress(pos + total_written);
                            }
                        }
                        ui.verbose(&format!(
                            "Extr: {} bytes to: {}",
                            total_written,
                            src.display()
                        ));
                    }

                    let nested_digests = Self::compute_manifest_digests(&src, ui)?;
                    ui.verbose(&format!("Nested: {} entries", nested_digests.len()));
                    ui.verbose(&format!("Sign: {} -> {}", src.display(), signed.display()));
                    Self::write_signed_zip(&src, &signed, keys, &nested_digests, ui)?;
                    ui.verbose(&format!("Signed: {:?}", signed));

                    let ft = FileTime::from_system_time(std::time::SystemTime::now());
                    set_file_times(&signed, ft, ft)?;
                    ui.verbose(&format!("Time: {:?}", signed));

                    let mut nested_file = BufReader::new(File::open(&signed)?);
                    let mut total_read = 0u64;
                    loop {
                        let n = nested_file.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        writer.write_all(&buf[..n])?;
                        total_read += n as u64;
                        if ui.has_progress_bar() {
                            ui.update_progress(pos + total_read);
                        }
                    }
                    ui.verbose(&format!("Embed: {} ({} bytes)", name, total_read));
                    ui.verbose(&format!("Cleanup: {:?}", tmpdir.path()));
                    pos += total_read + f.size();
                } else {
                    let mut total_read = 0u64;
                    loop {
                        let n = f.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        writer.write_all(&buf[..n])?;
                        total_read += n as u64;
                        if ui.has_progress_bar() {
                            ui.update_progress(pos + total_read);
                        }
                    }
                    ui.verbose(&format!("Copy: {} ({} bytes)", name, total_read));
                    pos += total_read;
                }

                if ui.verbose && !ui.has_progress_bar() {
                    ui.update_progress((i + 1) as u64);
                }
            }
            Ok::<(), SignerError>(())
        })?;

        if ui.very_verbose {
            ui.very_verbose(&format!("Output: {}", output.display()));
        } else {
            ui.verbose(&format!("Output: {}", output.display()));
        }

        if ui.verbose && ui.has_progress_bar() {
            ui.finish_progress();
        }
        writer.finish()?;
        ui.very_verbose("Finalized ZIP");
        let ft = FileTime::from_system_time(std::time::SystemTime::now());
        set_file_times(output, ft, ft)?;
        ui.very_verbose(&format!("Time: {}", output.display()));
        ui.very_verbose("Integrity check...");
        Self::verify_zip_integrity_with_ui(output, Some(ui))?;
        ui.very_verbose("Integrity OK");
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
        let mut writer =
            ZipWriter::new(BufWriter::with_capacity(BUFFER_SIZE, File::create(output)?));
        let mf = Self::gen_manifest(digests);
        let sf = Self::gen_sf(&mf, digests);
        let rsa = Self::gen_rsa(keys, &sf)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &mf, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa, timestamp)?;

        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;
        let mut total_size = 0u64;
        for i in 0..archive.len() {
            let f = archive.by_index(i)?;
            if !f.name().ends_with('/') && !Self::is_sig_file(f.name()) {
                if let Some(nb) = nested_files.get(f.name()) {
                    total_size += nb.len() as u64;
                } else {
                    total_size += f.size();
                }
            }
        }

        if ui.verbose {
            if total_size > 10 * 1024 * 1024 {
                ui.show_detailed_progress_bar(total_size, "Processing", "bytes");
            } else {
                ui.show_progress_bar(archive.len() as u64, "Writing files");
            }
        }

        PB.with(|local_buf| {
            let mut buf = local_buf.borrow_mut();
            let mut pos = 0u64;
            for i in 0..archive.len() {
                let mut f = archive.by_index(i)?;
                let name = f.name().to_string();

                if Self::is_sig_file(&name) {
                    continue;
                }

                writer.start_file(
                    &name,
                    FileOptions::<()>::default()
                        .compression_method(f.compression())
                        .last_modified_time(timestamp)
                        .unix_permissions(f.unix_mode().unwrap_or(0o644))
                        .with_alignment(4),
                )?;

                if let Some(nested_bytes) = nested_files.get(&name) {
                    ui.info(&format!("Embed: {}", name));
                    writer.write_all(nested_bytes)?;
                    if ui.has_progress_bar() {
                        ui.update_progress(pos + nested_bytes.len() as u64);
                    }
                    pos += nested_bytes.len() as u64;
                } else {
                    let mut total_read = 0u64;
                    loop {
                        let n = f.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        writer.write_all(&buf[..n])?;
                        total_read += n as u64;
                        if ui.has_progress_bar() {
                            ui.update_progress(pos + total_read);
                        }
                    }
                    pos += total_read;
                }

                if ui.verbose && !ui.has_progress_bar() {
                    ui.update_progress((i + 1) as u64);
                }
            }
            Ok::<(), SignerError>(())
        })?;

        ui.verbose(&format!("Sources: {}", output.display()));
        if ui.verbose && ui.has_progress_bar() {
            ui.finish_progress();
        }
        writer.finish()?;
        ui.verbose("Finalized ZIP");
        let ft = FileTime::from_system_time(std::time::SystemTime::now());
        set_file_times(output, ft, ft)?;
        ui.verbose(&format!("Time: {}", output.display()));
        ui.verbose("Integrity check...");
        Self::verify_zip_integrity_with_ui(output, Some(ui))?;
        ui.verbose("Integrity OK");
        Ok(())
    }

    fn is_sig_file(name: &str) -> bool {
        name.starts_with("META-INF/")
            && (name == MANIFEST_NAME
                || name == CERT_SF_NAME
                || name == CERT_RSA_NAME
                || name == CERT_PUBLIC_KEY_NAME
                || name.ends_with("/MANIFEST.MF")
                || name.ends_with(".SF")
                || name.ends_with(".RSA")
                || name.ends_with(".DSA")
                || name.ends_with(".EC"))
    }

    fn write_entry(
        w: &mut ZipWriter<BufWriter<File>>,
        n: &str,
        d: &[u8],
        t: DateTime,
    ) -> Result<(), SignerError> {
        let opts = FileOptions::<()>::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(t)
            .with_alignment(4);
        w.start_file(n, opts)?;
        w.write_all(d)?;
        Ok(())
    }

    fn write_manifest_line(out: &mut Vec<u8>, key: &str, value: &str) {
        let line = if Self::is_non_wrapping_field(key) {
            format!("{}: {}", key, value).into_bytes()
        } else {
            let line = format!("{}: {}", key, value).into_bytes();
            let mut result = Vec::with_capacity(line.len() + 10);
            let mut cursor = 0;
            let limit = if cursor == 0 { 72 } else { 71 };
            let chunk_size = std::cmp::min(line.len(), limit);
            result.extend_from_slice(&line[cursor..cursor + chunk_size]);
            result.extend_from_slice(b"\r\n");
            cursor += chunk_size;
            while cursor < line.len() {
                result.push(b' ');
                let remaining = line.len() - cursor;
                let chunk_size = std::cmp::min(remaining, 71);
                result.extend_from_slice(&line[cursor..cursor + chunk_size]);
                result.extend_from_slice(b"\r\n");
                cursor += chunk_size;
            }
            result
        };
        out.extend_from_slice(&line);
    }

    fn is_non_wrapping_field(key: &str) -> bool {
        key == "Name"
            || key.contains("-Digest")
            || key.contains("_Digest")
            || key == "SHA1-Digest-Manifest"
            || key == "SHA-256-Digest-Manifest"
            || key == "MD5-Digest-Manifest"
    }

    fn create_manifest_entry(name: &str, hash: &str) -> Vec<u8> {
        let mut entry = Vec::with_capacity(name.len() + hash.len() + 50);
        Self::write_manifest_line(&mut entry, "Name", name);
        Self::write_manifest_line(&mut entry, "SHA1-Digest", hash);
        entry.extend_from_slice(b"\r\n");
        entry
    }

    fn gen_manifest(digests: &BTreeMap<String, String>) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            50 + digests.len() * 100 + digests.values().map(|h| h.len()).sum::<usize>(),
        );
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
            if let Some(fh) = digests.get(name) {
                let meb = Self::create_manifest_entry(name, fh);
                let meh = CryptoEngine::compute_sha1(&meb);
                Self::write_manifest_line(&mut out, "Name", name);
                Self::write_manifest_line(&mut out, "SHA1-Digest", &meh);
                out.extend_from_slice(b"\r\n");
            }
        }
        out
    }

    fn gen_rsa(keys: &KeyChain, sf: &[u8]) -> Result<Vec<u8>, SignerError> {
        crate::pkcs7::gen_rsa(keys, sf)
    }

    pub fn verify_zip_integrity(path: &Path) -> Result<(), SignerError> {
        Self::verify_zip_integrity_with_ui(path, None)
    }

    pub fn verify_zip_integrity_with_ui(path: &Path, ui: Option<&Ui>) -> Result<(), SignerError> {
        let mut archive = ZipArchive::new(BufReader::new(File::open(path)?))?;
        let mut total_size = 0u64;
        for i in 0..archive.len() {
            if let Some(f) = archive.by_index(i).ok() {
                if !f.name().ends_with('/') {
                    total_size += f.size();
                }
            }
        }

        let mut buf = [0u8; BUFFER_SIZE];

        if let Some(ui) = ui {
            if total_size > 5 * 1024 * 1024 {
                ui.show_detailed_progress_bar(total_size, "Integrity", "bytes");
                let mut pos = 0u64;
                for i in 0..archive.len() {
                    let mut f = archive.by_index(i)?;
                    let mut hasher = Crc32::new();
                    loop {
                        let n = f.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        hasher.update(&buf[..n]);
                        pos += n as u64;
                        ui.update_progress(pos);
                    }
                    let (s, c) = (f.crc32(), hasher.finalize());
                    if s != c {
                        ui.finish_progress();
                        return Err(SignerError::Validation(format!(
                            "CRC: `{}` s={:#010x}, c={:#010x}",
                            f.name(),
                            s,
                            c
                        )));
                    }
                }
                ui.finish_progress();
            } else {
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
                    let (s, c) = (f.crc32(), hasher.finalize());
                    if s != c {
                        return Err(SignerError::Validation(format!(
                            "CRC: `{}` s={:#010x}, c={:#010x}",
                            f.name(),
                            s,
                            c
                        )));
                    }
                }
            }
        } else {
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
                let (s, c) = (f.crc32(), hasher.finalize());
                if s != c {
                    return Err(SignerError::Validation(format!(
                        "CRC: `{}` s={:#010x}, c={:#010x}",
                        f.name(),
                        s,
                        c
                    )));
                }
            }
        }
        Ok(())
    }
}
