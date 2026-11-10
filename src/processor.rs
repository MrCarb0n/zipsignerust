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

use crate::{
    crypto::CryptoEngine, error::SignerError, keys::KeyChain, ui::Ui, APP_NAME, BUFFER_SIZE,
    CERT_RSA_NAME, CERT_SF_NAME, MANIFEST_NAME,
};
use crc32fast::Hasher as Crc32;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};
use tempfile::tempdir;
use zip::{
    write::{FileOptions, ZipWriter},
    CompressionMethod, DateTime, ZipArchive,
};

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
        Self::reject_duplicate_entries(path)?;
        let mut archive = ZipArchive::new(BufReader::new(File::open(path)?))?;
        let len = archive.len();
        ui.debug(&format!("Digests: {} entries in {}", len, path.display()));

        let mut stats = (0u64, 0u64); // (total_size, non_sig_count)
        for i in 0..len {
            if let Ok(f) = archive.by_index(i) {
                let name = f.name();
                if !name.ends_with('/') && !Self::is_sig_file(name) {
                    stats.0 += f.size();
                    stats.1 += 1;
                }
            }
        }
        ui.debug(&format!("Process: {} files ({} bytes)", stats.1, stats.0));

        if ui.verbose && stats.1 > 0 {
            if stats.0 > 10 * 1024 * 1024 {
                ui.show_detailed_progress_bar(stats.0, "Manifest digests", "bytes");
            } else if stats.1 > 10 {
                ui.show_progress_bar(stats.1, "Manifest digests");
            } else {
                ui.info("Skipping progress bar: <10 files");
            }
        }

        let (mut digests, mut pos) = (BTreeMap::new(), 0u64);
        for i in 0..len {
            let mut f = archive.by_index(i)?;
            let name = f.name().to_string();

            if !name.ends_with('/') && !Self::is_sig_file(&name) {
                ui.debug(&format!("SHA-256: {} ({} bytes)", name, f.size()));
                let digest =
                    CryptoEngine::compute_stream_sha256_with_ui(&mut f, Some(ui), Some(&name))?;
                digests.insert(name, digest);
                if ui.has_progress_bar() {
                    ui.update_progress(pos + f.size());
                    pos += f.size();
                }
            }
        }
        ui.debug(&format!("Digests: {} files processed", digests.len()));
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
        Self::reject_duplicate_entries(path)?;
        let mut archive = ZipArchive::new(BufReader::new(File::open(path)?))?;
        let (mut digests, mut nested_files) = (BTreeMap::new(), BTreeMap::new());

        for i in 0..archive.len() {
            let mut f = archive.by_index(i)?;
            let name = f.name().to_string();

            if name.ends_with('/') || Self::is_sig_file(&name) {
                continue;
            }

            if name.ends_with(".zip") {
                ui.debug(&format!("Nested: {}", name));
                let tmpdir = tempdir()?;
                let (src, signed) = (
                    tmpdir.path().join("nested-src.zip"),
                    tmpdir.path().join("nested-signed.zip"),
                );

                ui.debug(&format!("Tmp: {:?}", tmpdir.path()));
                ui.info(&format!("Dir: {:?}", tmpdir.path()));
                ui.debug(&format!("Extr: {:?}", src));

                {
                    let mut out = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&src)?;
                    std::io::copy(&mut f, &mut out)?;
                    ui.debug(&format!("Extr: {} -> {}", name, src.display()));
                }

                Self::sign_nested_src(&src, &signed, keys, ui)?;

                let nested_bytes = fs::read(&signed)?;
                let digest = CryptoEngine::compute_sha256(&nested_bytes);
                digests.insert(name.clone(), digest.clone());
                nested_files.insert(name.clone(), nested_bytes);
                ui.debug(&format!("Proc: {} -> SHA-256: {}", name, &digest[..8]));
                ui.debug(&format!("Cleanup: {:?}", tmpdir.path()));
            } else {
                let digest =
                    CryptoEngine::compute_stream_sha256_with_ui(&mut f, Some(ui), Some(&name))?;
                digests.insert(name.clone(), digest.clone());
                ui.debug(&format!("Digest: {} -> SHA-256: {}", name, &digest[..8]));
            }
        }
        Ok(NestedDigests {
            digests,
            nested_files,
        })
    }

    /// Sign an extracted nested archive: digest its contents (handling any
    /// zips inside it recursively) and write the signed copy next to it.
    fn sign_nested_src(
        src: &Path,
        signed: &Path,
        keys: &KeyChain,
        ui: &Ui,
    ) -> Result<(), SignerError> {
        let nested = Self::compute_digests_prepare_nested(src, keys, ui)?;
        ui.debug(&format!("Nested: {} entries", nested.digests.len()));
        Self::write_signed_zip_with_sources(
            src,
            signed,
            keys,
            &nested.digests,
            &nested.nested_files,
            ui,
        )?;
        ui.debug(&format!("Signed: {:?}", signed));
        Ok(())
    }

    /// Sum of entry sizes, using pre-signed bytes where available.
    fn total_entry_size(
        archive: &mut ZipArchive<BufReader<File>>,
        nested_files: Option<&BTreeMap<String, Vec<u8>>>,
    ) -> Result<u64, SignerError> {
        let mut total = 0u64;
        for i in 0..archive.len() {
            let f = archive.by_index(i)?;
            if !f.name().ends_with('/') && !Self::is_sig_file(f.name()) {
                total += nested_files
                    .and_then(|m| m.get(f.name()))
                    .map(|b| b.len() as u64)
                    .unwrap_or_else(|| f.size());
            }
        }
        Ok(total)
    }

    fn show_write_progress(ui: &Ui, total_size: u64, file_count: u64) {
        if ui.verbose {
            if total_size > 10 * 1024 * 1024 {
                ui.show_detailed_progress_bar(total_size, "Processing", "bytes");
            } else {
                ui.show_progress_bar(file_count, "Writing files");
            }
        }
    }

    /// Copy entry bytes through, advancing the progress bar.
    fn copy_tracked<R: Read, W: Write>(
        reader: &mut R,
        writer: &mut W,
        buf: &mut [u8],
        ui: &Ui,
        pos: u64,
    ) -> Result<u64, SignerError> {
        let mut total = 0u64;
        loop {
            let n = reader.read(buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            total += n as u64;
            if ui.has_progress_bar() {
                ui.update_progress(pos + total);
            }
        }
        Ok(total)
    }

    fn start_copied_entry(
        writer: &mut ZipWriter<BufWriter<File>>,
        name: &str,
        compression: CompressionMethod,
        unix_mode: u32,
        timestamp: DateTime,
    ) -> Result<(), SignerError> {
        writer.start_file(
            name,
            FileOptions::<()>::default()
                .compression_method(compression)
                .last_modified_time(timestamp)
                .unix_permissions(unix_mode)
                .with_alignment(4),
        )?;
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
        let mut writer = Self::init_zip_writer(output, keys, digests, timestamp)?;

        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;
        let total_size = Self::total_entry_size(&mut archive, Some(nested_files))?;

        Self::reject_duplicate_entries(input)?;
        Self::show_write_progress(ui, total_size, archive.len() as u64);

        let mut buf = vec![0u8; BUFFER_SIZE];
        {
            let mut pos = 0u64;
            for i in 0..archive.len() {
                let mut f = archive.by_index(i)?;
                let name = f.name().to_string();

                if Self::is_sig_file(&name) {
                    continue;
                }

                let (compression, mode) = (f.compression(), f.unix_mode().unwrap_or(0o644));
                Self::start_copied_entry(&mut writer, &name, compression, mode, timestamp)?;

                if let Some(nested_bytes) = nested_files.get(&name) {
                    ui.info(&format!("Embed: {}", name));
                    writer.write_all(nested_bytes)?;
                    if ui.has_progress_bar() {
                        ui.update_progress(pos + nested_bytes.len() as u64);
                    }
                    pos += nested_bytes.len() as u64;
                } else {
                    pos += Self::copy_tracked(&mut f, &mut writer, &mut buf, ui, pos)?;
                }

                if ui.verbose && !ui.has_progress_bar() {
                    ui.update_progress((i + 1) as u64);
                }
            }
            Ok::<(), SignerError>(())
        }?;

        Self::finalize_zip_writer(writer, output, ui, "Sources")?;
        Ok(())
    }

    fn init_zip_writer(
        output: &Path,
        keys: &KeyChain,
        digests: &BTreeMap<String, String>,
        timestamp: DateTime,
    ) -> Result<ZipWriter<BufWriter<File>>, SignerError> {
        let mut writer =
            ZipWriter::new(BufWriter::with_capacity(BUFFER_SIZE, File::create(output)?));
        let mf = Self::gen_manifest(digests)?;
        let sf = Self::gen_sf(&mf, digests)?;
        let rsa = Self::gen_rsa(keys, &sf)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &mf, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa, timestamp)?;

        Ok(writer)
    }

    fn finalize_zip_writer(
        writer: ZipWriter<BufWriter<File>>,
        output: &Path,
        ui: &Ui,
        label: &str,
    ) -> Result<(), SignerError> {
        if ui.verbose && ui.has_progress_bar() {
            ui.finish_progress();
        }
        writer.finish()?;
        ui.debug(&format!("{}: {}", label, output.display()));
        // NOTE: the output file's mtime is left to the OS; only ZIP entry
        // timestamps use the certificate's `notBefore` for reproducible builds.
        ui.debug("Integrity check...");
        Self::verify_zip_integrity_with_ui(output, Some(ui))?;
        ui.debug("Integrity OK");
        Ok(())
    }

    /// One shared digest-field name for everything this tool writes.
    pub(crate) const DIGEST_FIELD: &'static str = "SHA-256-Digest";

    pub(crate) fn is_sig_file(name: &str) -> bool {
        // JAR signature entries sit directly in META-INF/, never in a subdir.
        let Some(rest) = name.strip_prefix("META-INF/") else {
            return false;
        };
        !rest.contains('/')
            && (rest == "MANIFEST.MF"
                || rest.ends_with(".SF")
                || rest.ends_with(".RSA")
                || rest.ends_with(".DSA")
                || rest.ends_with(".EC"))
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

    pub(crate) fn write_manifest_line(
        out: &mut Vec<u8>,
        key: &str,
        value: &str,
    ) -> Result<(), SignerError> {
        if key.contains('\r')
            || key.contains('\n')
            || key.contains(':')
            || value.contains('\r')
            || value.contains('\n')
        {
            return Err(SignerError::Validation(format!(
                "Invalid manifest header characters in '{}'",
                key
            )));
        }
        let line = format!("{}: {}", key, value);
        let bytes = line.as_bytes();
        let mut start = 0usize;
        let mut limit = 72usize;
        while start < bytes.len() {
            let mut end = (start + limit).min(bytes.len());
            while end > start && end < bytes.len() && !line.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                return Err(SignerError::Validation(
                    "Cannot wrap manifest header line".into(),
                ));
            }
            if start == 0 {
                out.extend_from_slice(&bytes[start..end]);
            } else {
                out.push(b' ');
                out.extend_from_slice(&bytes[start..end]);
            }
            out.extend_from_slice(b"\r\n");
            start = end;
            limit = 71;
        }
        Ok(())
    }

    pub(crate) fn create_manifest_entry(
        name: &str,
        field: &str,
        hash: &str,
    ) -> Result<Vec<u8>, SignerError> {
        let mut entry = Vec::with_capacity(name.len() + hash.len() + 50);
        Self::write_manifest_line(&mut entry, "Name", name)?;
        Self::write_manifest_line(&mut entry, field, hash)?;
        entry.extend_from_slice(b"\r\n");
        Ok(entry)
    }

    fn gen_manifest(digests: &BTreeMap<String, String>) -> Result<Vec<u8>, SignerError> {
        let mut out = Vec::with_capacity(
            50 + digests.len() * 100 + digests.values().map(|h| h.len()).sum::<usize>(),
        );
        out.extend_from_slice(b"Manifest-Version: 1.0\r\n");
        Self::write_manifest_line(&mut out, "Created-By", APP_NAME)?;
        out.extend_from_slice(b"\r\n");
        for (name, hash) in digests {
            out.extend(Self::create_manifest_entry(name, Self::DIGEST_FIELD, hash)?);
        }
        Ok(out)
    }

    fn gen_sf(
        manifest_bytes: &[u8],
        digests: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>, SignerError> {
        let mut out = Vec::new();
        out.extend_from_slice(b"Signature-Version: 1.0\r\n");
        Self::write_manifest_line(&mut out, "Created-By", APP_NAME)?;
        let manifest_hash = CryptoEngine::compute_sha256(manifest_bytes);
        Self::write_manifest_line(&mut out, "SHA-256-Digest-Manifest", &manifest_hash)?;
        out.extend_from_slice(b"\r\n");
        for name in digests.keys() {
            if let Some(fh) = digests.get(name) {
                let meb = Self::create_manifest_entry(name, Self::DIGEST_FIELD, fh)?;
                let meh = CryptoEngine::compute_sha256(&meb);
                Self::write_manifest_line(&mut out, "Name", name)?;
                Self::write_manifest_line(&mut out, Self::DIGEST_FIELD, &meh)?;
                out.extend_from_slice(b"\r\n");
            }
        }
        Ok(out)
    }

    fn gen_rsa(keys: &KeyChain, sf: &[u8]) -> Result<Vec<u8>, SignerError> {
        crate::pkcs7::gen_rsa(keys, sf)
    }

    pub fn verify_zip_integrity(path: &Path) -> Result<(), SignerError> {
        Self::verify_zip_integrity_with_ui(path, None)
    }

    fn verify_entry_crc(f: &mut zip::read::ZipFile<'_>, buf: &mut [u8]) -> Result<(), SignerError> {
        let mut hasher = Crc32::new();
        loop {
            let n = f.read(buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let (stored, computed) = (f.crc32(), hasher.finalize());
        if stored != computed {
            return Err(SignerError::Validation(format!(
                "CRC: `{}` s={:#010x}, c={:#010x}",
                f.name(),
                stored,
                computed
            )));
        }
        Ok(())
    }

    pub fn reject_duplicate_entries(path: &Path) -> Result<(), SignerError> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        let read_len = len.min(70_000) as usize;
        file.seek(SeekFrom::End(-(read_len as i64)))?;
        let mut tail = vec![0u8; read_len];
        file.read_exact(&mut tail)?;
        let eocd = tail
            .windows(22)
            .rposition(|w| w.starts_with(b"PK\x05\x06"))
            .ok_or_else(|| SignerError::Validation("Cannot locate ZIP central directory".into()))?;
        let total = u16::from_le_bytes(tail[eocd + 10..eocd + 12].try_into().unwrap()) as usize;
        let cd_size = u32::from_le_bytes(tail[eocd + 12..eocd + 16].try_into().unwrap()) as u64;
        let cd_off = u32::from_le_bytes(tail[eocd + 16..eocd + 20].try_into().unwrap()) as u64;
        if cd_off == u32::MAX as u64 || cd_size == u32::MAX as u64 || total == 0xFFFF {
            // ZIP64/complex: best effort; rely on downstream checks.
            return Ok(());
        }
        file.seek(SeekFrom::Start(cd_off))?;
        let mut cd = vec![0u8; cd_size as usize];
        file.read_exact(&mut cd)?;
        let mut seen = BTreeSet::new();
        let mut i = 0usize;
        let mut count = 0usize;
        while i + 46 <= cd.len() && count < total {
            if &cd[i..i + 4] != b"PK\x01\x02" {
                break;
            }
            let name_len = u16::from_le_bytes(cd[i + 28..i + 30].try_into().unwrap()) as usize;
            let extra_len = u16::from_le_bytes(cd[i + 30..i + 32].try_into().unwrap()) as usize;
            let comment_len = u16::from_le_bytes(cd[i + 32..i + 34].try_into().unwrap()) as usize;
            let start = i + 46;
            let end = start + name_len;
            if end > cd.len() {
                break;
            }
            let name = String::from_utf8_lossy(&cd[start..end]).to_string();
            if !seen.insert(name.clone()) {
                return Err(SignerError::Validation(format!(
                    "Duplicate archive entry '{}'",
                    name
                )));
            }
            i = end + extra_len + comment_len;
            count += 1;
        }
        Ok(())
    }

    pub fn verify_zip_integrity_with_ui(path: &Path, ui: Option<&Ui>) -> Result<(), SignerError> {
        Self::reject_duplicate_entries(path)?;
        let mut archive = ZipArchive::new(BufReader::new(File::open(path)?))?;
        let mut total_size = 0u64;
        for i in 0..archive.len() {
            if let Ok(f) = archive.by_index(i) {
                if !f.name().ends_with('/') {
                    total_size += f.size();
                }
            }
        }

        let mut buf = [0u8; BUFFER_SIZE];
        let show_progress = ui.is_some() && total_size > 5 * 1024 * 1024;

        if show_progress {
            if let Some(ui) = ui {
                ui.show_detailed_progress_bar(total_size, "Integrity", "bytes");
            }
        }

        let mut pos = 0u64;
        for i in 0..archive.len() {
            let mut f = archive.by_index(i)?;
            Self::verify_entry_crc(&mut f, &mut buf)?;
            if show_progress {
                pos += f.size();
                if let Some(ui) = ui {
                    ui.update_progress(pos);
                }
            }
        }

        if show_progress {
            if let Some(ui) = ui {
                ui.finish_progress();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sig_file_manifest() {
        assert!(ArtifactProcessor::is_sig_file("META-INF/MANIFEST.MF"));
    }

    #[test]
    fn test_is_sig_file_cert_sf() {
        assert!(ArtifactProcessor::is_sig_file("META-INF/CERT.SF"));
    }

    #[test]
    fn test_is_sig_file_cert_rsa() {
        assert!(ArtifactProcessor::is_sig_file("META-INF/CERT.RSA"));
    }

    #[test]
    fn test_is_sig_file_other_sf() {
        assert!(ArtifactProcessor::is_sig_file("META-INF/ANDROID.SF"));
        assert!(ArtifactProcessor::is_sig_file("META-INF/CERT.SF"));
    }

    #[test]
    fn test_is_sig_file_other_rsa() {
        assert!(ArtifactProcessor::is_sig_file("META-INF/CERT.RSA"));
        assert!(ArtifactProcessor::is_sig_file("META-INF/SIGN.RSA"));
    }

    #[test]
    fn test_is_sig_file_rejects_normal_file() {
        assert!(!ArtifactProcessor::is_sig_file("classes.dex"));
        assert!(!ArtifactProcessor::is_sig_file("AndroidManifest.xml"));
    }

    #[test]
    fn test_is_sig_file_rejects_meta_inf_subdir() {
        assert!(!ArtifactProcessor::is_sig_file(
            "META-INF/services/somefile"
        ));
        assert!(!ArtifactProcessor::is_sig_file("META-INF/services/foo.RSA"));
        assert!(!ArtifactProcessor::is_sig_file("META-INF/sub/MANIFEST.MF"));
    }

    #[test]
    fn test_write_manifest_line_short() {
        let mut out = Vec::new();
        ArtifactProcessor::write_manifest_line(&mut out, "Name", "test.txt").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "Name: test.txt\r\n");
    }

    #[test]
    fn test_write_manifest_line_wrapping() {
        let long_val = "A".repeat(100);
        let mut out = Vec::new();
        ArtifactProcessor::write_manifest_line(&mut out, "Created-By", &long_val).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("Created-By: "));
        assert!(s.ends_with("\r\n"));
        assert!(s.len() > 100);
        let lines: Vec<&str> = s.split("\r\n").collect();
        for line in &lines[1..] {
            if !line.is_empty() {
                assert!(
                    line.starts_with(' '),
                    "wrapped line should start with space: {:?}",
                    line
                );
            }
        }
    }

    #[test]
    fn test_write_manifest_line_rejects_newline() {
        let mut out = Vec::new();
        assert!(ArtifactProcessor::write_manifest_line(&mut out, "Name", "a\nb").is_err());
    }

    #[test]
    fn test_create_manifest_entry() {
        let entry = ArtifactProcessor::create_manifest_entry(
            "test.txt",
            ArtifactProcessor::DIGEST_FIELD,
            "abc123",
        )
        .unwrap();
        let s = String::from_utf8(entry).unwrap();
        assert!(s.contains("Name: test.txt"));
        assert!(s.contains("SHA-256-Digest: abc123"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_gen_manifest_empty() {
        let digests = BTreeMap::new();
        let mf = ArtifactProcessor::gen_manifest(&digests).unwrap();
        let s = String::from_utf8(mf).unwrap();
        assert!(s.starts_with("Manifest-Version: 1.0\r\n"));
        assert!(s.contains("Created-By"));
        assert_eq!(s.matches("Name:").count(), 0);
    }

    #[test]
    fn test_gen_manifest_entries() {
        let mut digests = BTreeMap::new();
        digests.insert("file1.txt".into(), "hash1".into());
        digests.insert("file2.txt".into(), "hash2".into());
        let mf = ArtifactProcessor::gen_manifest(&digests).unwrap();
        let s = String::from_utf8(mf).unwrap();
        assert!(s.contains("Name: file1.txt"));
        assert!(s.contains("Name: file2.txt"));
        assert!(s.contains("SHA-256-Digest: hash1"));
        assert!(s.contains("SHA-256-Digest: hash2"));
    }

    #[test]
    fn test_gen_sf_manifest_hash() {
        let mut digests = BTreeMap::new();
        digests.insert("a.txt".into(), "h1".into());
        let mf = ArtifactProcessor::gen_manifest(&digests).unwrap();
        let sf = ArtifactProcessor::gen_sf(&mf, &digests).unwrap();
        let s = String::from_utf8(sf).unwrap();
        assert!(s.contains("Signature-Version: 1.0"));
        assert!(s.contains("SHA-256-Digest-Manifest"));
        assert!(s.contains("Name: a.txt"));
    }
}
