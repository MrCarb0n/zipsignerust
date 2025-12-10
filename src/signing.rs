/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use ::pem as pem_crate;
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use crc32fast::Hasher as Crc32;
use filetime::{set_file_times, FileTime};
use rayon::prelude::*;
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
    error::SignerError, ui::Ui, APP_NAME, BUFFER_SIZE, CERT_RSA_NAME, CERT_SF_NAME, MANIFEST_NAME,
};

const RSA_SIGNATURE_SCHEME: &dyn signature::RsaEncoding = &signature::RSA_PKCS1_SHA256;

const RSA_VERIFICATION_ALGORITHM: &'static dyn signature::VerificationAlgorithm =
    &signature::RSA_PKCS1_2048_8192_SHA256;

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

pub struct KeyChain {
    pub private_key: Option<RsaKeyPair>,
    pub public_key: Option<UnparsedPublicKey<Vec<u8>>>,
    pub cert_not_before: Option<DateTime>,
}

// Type alias to satisfy clippy::type-complexity
type LoadedPublicKey = (Option<UnparsedPublicKey<Vec<u8>>>, Option<DateTime>);

impl KeyChain {
    pub fn new(
        priv_path: Option<&Path>,
        pub_path: Option<&Path>,
        ui: &Ui,
    ) -> Result<Self, SignerError> {
        let private_key = Self::load_private_key(priv_path, ui)?;
        let (public_key, cert_not_before) = Self::load_public_key(pub_path, ui)?;

        if private_key.is_none() && public_key.is_none() {
            return Err(SignerError::Config(
                "Failed to load any keys (both custom and default failed).".into(),
            ));
        }

        Ok(Self {
            private_key,
            public_key,
            cert_not_before,
        })
    }

    fn load_private_key(path: Option<&Path>, ui: &Ui) -> Result<Option<RsaKeyPair>, SignerError> {
        let content = if let Some(p) = path {
            Self::check_key_permissions(p, ui)?;
            fs::read(p)?
        } else {
            crate::default_keys::PRIVATE_KEY.as_bytes().to_vec()
        };

        let pem = pem_crate::parse(&content)?;
        let key_pair = RsaKeyPair::from_pkcs8(&pem.contents)
            .map_err(|e| SignerError::Config(format!("Invalid Private Key: {}", e)))?;

        Ok(Some(key_pair))
    }

    fn load_public_key(path: Option<&Path>, ui: &Ui) -> Result<LoadedPublicKey, SignerError> {
        let content = if let Some(p) = path {
            fs::read(p)?
        } else {
            crate::default_keys::PUBLIC_KEY.as_bytes().to_vec()
        };

        let pem = pem_crate::parse(&content)?;
        let (_, cert) = X509Certificate::from_der(&pem.contents)
            .map_err(|e| SignerError::Config(format!("Invalid certificate: {:?}", e)))?;

        let pk_der = cert.public_key().subject_public_key.data.to_vec();
        let nb = Some(Self::asn1_to_zip_datetime(cert.validity().not_before, ui));

        Ok((
            Some(UnparsedPublicKey::new(RSA_VERIFICATION_ALGORITHM, pk_der)),
            nb,
        ))
    }

    pub fn get_reproducible_timestamp(&self) -> DateTime {
        if let Some(dt) = &self.cert_not_before {
            return *dt;
        }
        // Fallback to 2100-01-01 11:11:11 UTC (Futuristic fallback)
        DateTime::from_date_and_time(2100, 1, 1, 11, 11, 11).unwrap()
    }

    #[cfg(unix)]
    fn check_key_permissions(path: &Path, ui: &Ui) -> Result<(), SignerError> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let permissions = metadata.permissions().mode();
        if permissions & 0o077 != 0 {
            ui.warn(&format!(
                "Private key '{}' is accessible by others (mode {:o}).",
                path.display(),
                permissions
            ));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_key_permissions(_path: &Path, _ui: &Ui) -> Result<(), SignerError> {
        Ok(())
    }

    fn asn1_to_zip_datetime(asn1: ASN1Time, ui: &Ui) -> DateTime {
        let dt = asn1.to_datetime();

        // 1. Clamp minimal year to 2008 (Android epoch) to avoid 1980/1996 issues
        let year = (dt.year() as u16).clamp(2008, 2107);

        let month = dt.month() as u8;
        let day = dt.day();
        let hour = dt.hour();
        let minute = dt.minute();
        // ZIP seconds are divided by 2, so precision is 2 seconds.
        let second = dt.second();

        DateTime::from_date_and_time(year, month, day, hour, minute, second).unwrap_or_else(|_| {
            ui.error("Failed to create DateTime from certificate. Fallback to 2100-01-01.");
            DateTime::from_date_and_time(2100, 1, 1, 11, 11, 11).unwrap()
        })
    }
}

pub struct ArtifactProcessor;

pub struct NestedDigests {
    pub digests: BTreeMap<String, String>,
    pub nested_sources: BTreeMap<String, Vec<u8>>,
}

impl ArtifactProcessor {
    pub fn compute_manifest_digests(path: &Path) -> Result<BTreeMap<String, String>, SignerError> {
        let file = File::open(path)?;
        let archive = ZipArchive::new(BufReader::new(file))?;
        let len = archive.len();

        let indices: Vec<usize> = (0..len).collect();

        let results: Vec<Result<(String, String), SignerError>> = indices
            .par_iter()
            .map(|&i| {
                let f = File::open(path)?;
                let mut local_archive = ZipArchive::new(BufReader::new(f))?;
                let mut zip_file = local_archive.by_index(i)?;

                let name = zip_file.name().to_string();
                if name.ends_with('/') || name.starts_with("META-INF/") {
                    return Ok(("".to_string(), "".to_string()));
                }

                let digest = CryptoEngine::compute_stream_sha1(&mut zip_file)?;
                Ok((name, digest))
            })
            .collect();

        let mut digests = BTreeMap::new();
        for res in results {
            let (name, digest) = res?;
            if !name.is_empty() {
                digests.insert(name, digest);
            }
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
                Self::write_signed_zip(&nested_src, &nested_signed, keys, &nested_digests, ui)?;

                let nested_bytes = fs::read(&nested_signed)?;
                let digest = CryptoEngine::compute_sha1(&nested_bytes);
                digests.insert(name.clone(), digest);
                nested_sources.insert(name, nested_bytes);
            } else {
                let digest = CryptoEngine::compute_stream_sha1(&mut zip_file)?;
                digests.insert(name, digest);
            }
        }

        Ok(NestedDigests {
            digests,
            nested_sources,
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

        let out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output)?;
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
                    .unix_permissions(file.unix_mode().unwrap_or(0o644))
                    .with_alignment(4);

                writer.start_file(&name, options)?;
                if name.ends_with(".zip") || name.ends_with(".jar") || name.ends_with(".apk") {
                    ui.info(&format!("Signing nested archive: `{}`", name));
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

                    let nested_digests = Self::compute_manifest_digests(&nested_src)?;
                    Self::write_signed_zip(&nested_src, &nested_signed, keys, &nested_digests, ui)?;

                    // Use UTC logic for filesystem timestamp
                    let ft =
                        FileTime::from_unix_time(Self::zip_datetime_to_unix(&timestamp) as i64, 0);
                    set_file_times(&nested_signed, ft, ft)?;
                    ui.verbose(&format!(
                        "Set mtime on nested archive: `{}`",
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
        }
        writer.finish()?;
        let now = std::time::SystemTime::now();
        let ft = FileTime::from_system_time(now);
        set_file_times(output, ft, ft)?;
        ui.verbose(&format!("Set mtime on output: `{}`", output.display()));
        Self::verify_zip_integrity(output)?;
        Ok(())
    }

    pub fn write_signed_zip_with_sources(
        input: &Path,
        output: &Path,
        keys: &KeyChain,
        digests: &BTreeMap<String, String>,
        nested_sources: &BTreeMap<String, Vec<u8>>,
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

        let out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output)?;
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
                    .unix_permissions(file.unix_mode().unwrap_or(0o644))
                    .with_alignment(4);

                writer.start_file(&name, options)?;

                if let Some(nested_bytes) = nested_sources.get(&name) {
                    ui.info(&format!("Embedding signed nested archive: `{}`", name));
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
        ui.verbose(&format!("Set mtime on output: `{}`", output.display()));
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
        let mut entry = Vec::new();
        Self::write_manifest_line(&mut entry, "Name", name);
        Self::write_manifest_line(&mut entry, "SHA1-Digest", hash);
        entry.extend_from_slice(b"\r\n");
        entry
    }

    fn gen_manifest(digests: &BTreeMap<String, String>) -> Vec<u8> {
        let mut out = Vec::new();
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
        let key_pair = keys
            .private_key
            .as_ref()
            .ok_or(SignerError::Config("Private Key Missing".into()))?;
        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        let rng = SystemRandom::new();
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
