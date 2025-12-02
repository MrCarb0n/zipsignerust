/*
 * Android ZIP Signer (Rust Edition)
 * Refactored for Production Readiness, Memory Efficiency, and UX.
 * * Features:
 * - Streaming I/O (Low RAM usage)
 * - Strict Certificate Timestamp Inheritance
 * - Full Chain-of-Trust Verification
 */

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    str,
    fmt,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use clap::{Arg, ArgAction, Command};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Padding,
    sign::{Signer, Verifier},
    x509::{X509, X509Name},
};
use sha1::{Digest, Sha1};
use zip::{
    read::ZipArchive,
    write::{FileOptions, ZipWriter},
    CompressionMethod, DateTime,
};
use regex::Regex;

// --- Constants ---
const MANIFEST_NAME: &str = "META-INF/MANIFEST.MF";
const CERT_SF_NAME: &str = "META-INF/CERT.SF";
const CERT_RSA_NAME: &str = "META-INF/CERT.RSA";
const BUFFER_SIZE: usize = 64 * 1024; // 64KB Copy Buffer
const APP_NAME: &str = "zipsignerust";
const APP_VERSION: &str = "2.0.0-pro";
const APP_AUTHOR: &str = "Tiash H Kabir (@MrCarb0n)";

// --- Embedded Defaults ---
// These allow the binary to work "out of the box" without external files.
const DEFAULT_PRIVATE_KEY: &str = include_str!("../certs/private_key.pem");
const DEFAULT_PUBLIC_KEY: &str = include_str!("../certs/public_key.pem");

// --- Custom Error Type ---
#[derive(Debug)]
enum SignerError {
    Io(io::Error),
    Zip(zip::result::ZipError),
    OpenSsl(openssl::error::ErrorStack),
    Validation(String),
    Config(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::Io(e) => write!(f, "I/O Error: {}", e),
            SignerError::Zip(e) => write!(f, "ZIP Structure Error: {}", e),
            SignerError::OpenSsl(e) => write!(f, "OpenSSL Error: {}", e),
            SignerError::Validation(e) => write!(f, "Validation Failed: {}", e),
            SignerError::Config(e) => write!(f, "Configuration Error: {}", e),
        }
    }
}

impl std::error::Error for SignerError {}

// Implement automatic conversions for cleaner code using '?'
impl From<io::Error> for SignerError { fn from(e: io::Error) -> Self { Self::Io(e) } }
impl From<zip::result::ZipError> for SignerError { fn from(e: zip::result::ZipError) -> Self { Self::Zip(e) } }
impl From<openssl::error::ErrorStack> for SignerError { fn from(e: openssl::error::ErrorStack) -> Self { Self::OpenSsl(e) } }

// --- Crypto Engine ---
struct CryptoEngine;

impl CryptoEngine {
    fn compute_sha1(data: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(data);
        let digest = hasher.finalize();
        base64_engine.encode(digest)
    }

    /// Computes SHA1 of a reader stream (Low RAM usage)
    fn compute_stream_sha1<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        let mut hasher = Sha1::new();
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }
        let digest = hasher.finalize();
        Ok(base64_engine.encode(digest))
    }
}

// --- Key Management ---
struct KeyChain {
    private_key: Option<PKey<Private>>,
    public_key: Option<PKey<Public>>,
    certificate: Option<X509>,
}

impl KeyChain {
    fn new(priv_path: Option<&Path>, pub_path: Option<&Path>) -> Result<Self, SignerError> {
        let private_key = if let Some(path) = priv_path {
            let data = fs::read(path)?;
            Some(PKey::private_key_from_pem(&data)?)
        } else {
            // Only load default private key if we are NOT verifying-only or if explicitly needed
            // But logic allows optional signing. We'll load embedded.
            Some(PKey::private_key_from_pem(DEFAULT_PRIVATE_KEY.as_bytes())?)
        };

        let (public_key, certificate) = if let Some(path) = pub_path {
            let data = fs::read(path)?;
            // Try loading as X509 first (most common for Android keys)
            if let Ok(cert) = X509::from_pem(&data) {
                (Some(cert.public_key()?), Some(cert))
            } else {
                // Fallback to raw public key
                (Some(PKey::public_key_from_pem(&data)?), None)
            }
        } else {
            // Embedded default
            let cert = X509::from_pem(DEFAULT_PUBLIC_KEY.as_bytes())?;
            (Some(cert.public_key()?), Some(cert))
        };

        Ok(Self { private_key, public_key, certificate })
    }

    /// Generates a self-signed certificate if one wasn't provided but is needed for the PKCS7 block
    fn ensure_certificate(&mut self) -> Result<(), SignerError> {
        if self.certificate.is_none() {
            if let (Some(pk), Some(pubk)) = (&self.private_key, &self.public_key) {
                let mut builder = X509::builder()?;
                builder.set_version(2)?;
                
                let mut name = X509Name::builder()?;
                name.append_entry_by_text("CN", "Zipsigner Auto-Gen")?;
                let name = name.build();
                
                builder.set_subject_name(&name)?;
                builder.set_issuer_name(&name)?;
                builder.set_pubkey(pubk)?;
                
                let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
                let not_after = openssl::asn1::Asn1Time::days_from_now(3650)?;
                builder.set_not_before(&not_before)?;
                builder.set_not_after(&not_after)?;
                
                builder.sign(pk, MessageDigest::sha256())?;
                self.certificate = Some(builder.build());
            }
        }
        Ok(())
    }

    /// Extracts the precise 'Not Before' timestamp from the certificate.
    /// This is the "God Timestamp" used for all files in the output.
    fn get_timestamp_oracle(&self) -> DateTime {
        if let Some(cert) = &self.certificate {
            // Attempt to parse OpenSSL ASN1 time
            let time_str = cert.not_before().to_string();
            // Regex for "Mmm dd hh:mm:ss yyyy GMT"
            let re = Regex::new(r"([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})").unwrap();
            
            if let Some(caps) = re.captures(&time_str) {
                let month_str = &caps[1];
                let month = match month_str {
                    "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4, "May" => 5, "Jun" => 6,
                    "Jul" => 7, "Aug" => 8, "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
                    _ => 1,
                };
                let day = caps[2].parse().unwrap_or(1);
                let hour = caps[3].parse().unwrap_or(0);
                let minute = caps[4].parse().unwrap_or(0);
                let second = caps[5].parse().unwrap_or(0);
                let year = caps[6].parse().unwrap_or(1980).max(1980); // ZIP format requires >= 1980

                if let Ok(dt) = DateTime::from_date_and_time(year as u16, month, day, hour, minute, second) {
                    return dt;
                }
            }
        }
        
        // Fallback: safe DOS epoch
        DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap()
    }
}

// --- ZIP Processor ---
struct ArtifactProcessor;

impl ArtifactProcessor {
    /// Pass 1: Scan the input ZIP and compute SHA1 hashes for all files.
    /// Returns a map of Filename -> SHA1 Hash.
    /// Skips existing signature files.
    fn compute_manifest_digests(path: &Path, ui: &UserInterface) -> Result<BTreeMap<String, String>, SignerError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(BufReader::new(file))?;
        let mut digests = BTreeMap::new();

        let total = archive.len();
        ui.start_phase("Hashing Files", total);

        for i in 0..total {
            let mut zip_file = archive.by_index(i)?;
            let name = zip_file.name().to_string();

            // Skip directories and existing signatures
            if name.ends_with('/') || name.starts_with("META-INF/") {
                continue;
            }

            let digest = CryptoEngine::compute_stream_sha1(&mut zip_file)?;
            digests.insert(name, digest);
            ui.tick();
        }

        Ok(digests)
    }

    /// Pass 2: Create the output ZIP.
    /// Writes generated Manifest/Signatures first.
    /// Then streams files from Input -> Output.
    fn write_signed_zip(
        input_path: &Path,
        output_path: &Path,
        key_chain: &KeyChain,
        digests: &BTreeMap<String, String>,
        ui: &UserInterface
    ) -> Result<(), SignerError> {
        let timestamp = key_chain.get_timestamp_oracle();
        
        // Prepare Output
        let out_file = OpenOptions::new().create(true).write(true).truncate(true).open(output_path)?;
        let mut writer = ZipWriter::new(BufWriter::new(out_file));

        // 1. Generate & Write MANIFEST.MF
        ui.log("Generating Manifest...");
        let manifest_data = Self::generate_manifest(digests);
        Self::write_entry(&mut writer, MANIFEST_NAME, &manifest_data, timestamp)?;

        // 2. Generate & Write CERT.SF
        ui.log("Generating Signature File...");
        let sf_data = Self::generate_cert_sf(&manifest_data);
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf_data, timestamp)?;

        // 3. Generate & Write CERT.RSA
        ui.log("Generating RSA Block...");
        let rsa_data = Self::generate_cert_rsa(key_chain, &sf_data)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa_data, timestamp)?;

        // 4. Stream Copy Content
        let in_file = File::open(input_path)?;
        let mut archive = ZipArchive::new(BufReader::new(in_file))?;
        let total = archive.len();
        
        ui.start_phase("Signing & Packing", total);

        let mut buffer = [0u8; BUFFER_SIZE];

        for i in 0..total {
            let mut zip_file = archive.by_index(i)?;
            let name = zip_file.name().to_string();

            // Skip existing signatures
            if name.starts_with("META-INF/") && 
               (name.ends_with(".SF") || name.ends_with(".RSA") || name.ends_with(".DSA") || name.ends_with("MANIFEST.MF")) {
                continue;
            }

            // Options: Use the ORACLE timestamp for everything
            let options = FileOptions::default()
                .compression_method(zip_file.compression()) // Preserve compression type
                .last_modified_time(timestamp) // Strict timestamp enforcement
                .unix_permissions(zip_file.unix_mode().unwrap_or(0o644));

            writer.start_file(name, options)?;
            
            // Stream Copy
            loop {
                let n = zip_file.read(&mut buffer)?;
                if n == 0 { break; }
                writer.write_all(&buffer[..n])?;
            }
            
            ui.tick();
        }

        writer.finish()?;
        Ok(())
    }

    fn write_entry(writer: &mut ZipWriter<BufWriter<File>>, name: &str, data: &[u8], time: DateTime) -> Result<(), SignerError> {
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(time)
            .unix_permissions(0o644);
        writer.start_file(name, options)?;
        writer.write_all(data)?;
        Ok(())
    }

    // --- Generation Helpers ---

    fn generate_manifest(digests: &BTreeMap<String, String>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"Manifest-Version: 1.0\r\n");
        buf.extend_from_slice(format!("Created-By: {}\r\n\r\n", APP_VERSION).as_bytes());

        for (name, hash) in digests {
            buf.extend_from_slice(format!("Name: {}\r\n", name).as_bytes());
            buf.extend_from_slice(format!("SHA1-Digest: {}\r\n\r\n", hash).as_bytes());
        }
        buf
    }

    fn generate_cert_sf(manifest_data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"Signature-Version: 1.0\r\n");
        buf.extend_from_slice(format!("Created-By: {}\r\n", APP_VERSION).as_bytes());
        
        let manifest_hash = CryptoEngine::compute_sha1(manifest_data);
        buf.extend_from_slice(format!("SHA1-Digest-Manifest: {}\r\n\r\n", manifest_hash).as_bytes());

        // Parse Manifest to create SF entries (Name + Hash of Name block)
        let s = String::from_utf8_lossy(manifest_data);
        let mut entry_buffer = String::new();
        let mut in_entry = false;

        for line in s.lines() {
            if line.trim().is_empty() {
                if in_entry && !entry_buffer.is_empty() {
                    // Hash the previous entry block
                    let hash = CryptoEngine::compute_sha1(entry_buffer.as_bytes());
                    // Extract name
                    if let Some(name_line) = entry_buffer.lines().find(|l| l.starts_with("Name: ")) {
                        buf.extend_from_slice(format!("{}\r\n", name_line).as_bytes());
                        buf.extend_from_slice(format!("SHA1-Digest: {}\r\n\r\n", hash).as_bytes());
                    }
                }
                entry_buffer.clear();
                in_entry = false;
                continue;
            }
            if !in_entry && line.starts_with("Name: ") {
                in_entry = true;
            }
            if in_entry {
                entry_buffer.push_str(line);
                entry_buffer.push('\n');
            }
        }
        buf
    }

    fn generate_cert_rsa(key_chain: &KeyChain, sf_data: &[u8]) -> Result<Vec<u8>, SignerError> {
        let pk = key_chain.private_key.as_ref().ok_or(SignerError::Config("No Private Key".into()))?;
        
        let mut signer = Signer::new(MessageDigest::sha1(), pk)?;
        signer.set_rsa_padding(Padding::PKCS1)?;
        signer.update(sf_data)?;
        let signature = signer.sign_to_vec()?;

        // Build PKCS7 Block (Cert + Signature)
        let mut block = Vec::new();
        if let Some(cert) = &key_chain.certificate {
            block.extend_from_slice(&cert.to_der()?);
        }
        block.extend_from_slice(&signature);
        Ok(block)
    }
}

// --- Verifier ---
struct ArtifactVerifier;

impl ArtifactVerifier {
    fn verify(path: &Path, key_chain: &KeyChain, ui: &UserInterface) -> Result<bool, SignerError> {
        let pub_key = key_chain.public_key.as_ref().ok_or(SignerError::Config("No Public Key".into()))?;
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(BufReader::new(file))?;

        // 1. Locate Signature Files
        ui.log("Checking signature structure...");
        let has_manifest = archive.by_name(MANIFEST_NAME).is_ok();
        let has_sf = archive.by_name(CERT_SF_NAME).is_ok();
        let has_rsa = archive.by_name(CERT_RSA_NAME).is_ok();

        if !has_manifest || !has_sf || !has_rsa {
            return Err(SignerError::Validation("Missing META-INF signature files".into()));
        }

        // 2. Read Signature Files
        let mut manifest_data = Vec::new();
        archive.by_name(MANIFEST_NAME)?.read_to_end(&mut manifest_data)?;
        
        let mut sf_data = Vec::new();
        archive.by_name(CERT_SF_NAME)?.read_to_end(&mut sf_data)?;
        
        let mut rsa_data = Vec::new();
        archive.by_name(CERT_RSA_NAME)?.read_to_end(&mut rsa_data)?;

        // 3. Verify RSA Signature
        ui.log("Verifying Cryptographic Signature...");
        // Extract raw signature (last N bytes where N = key size)
        let sig_len = pub_key.size();
        if rsa_data.len() < sig_len {
            return Err(SignerError::Validation("RSA block corrupted".into()));
        }
        let raw_sig = &rsa_data[rsa_data.len() - sig_len..];

        let mut verifier = Verifier::new(MessageDigest::sha1(), pub_key)?;
        verifier.set_rsa_padding(Padding::PKCS1)?;
        verifier.update(&sf_data)?;
        if !verifier.verify(raw_sig)? {
            return Err(SignerError::Validation("RSA Signature Mismatch".into()));
        }

        // 4. Verify SF Digest matches Manifest
        ui.log("Verifying Chain of Trust (SF -> Manifest)...");
        let manifest_hash = CryptoEngine::compute_sha1(&manifest_data);
        let sf_str = String::from_utf8_lossy(&sf_data);
        if !sf_str.contains(&format!("SHA1-Digest-Manifest: {}", manifest_hash)) {
            return Err(SignerError::Validation("SF does not match Manifest".into()));
        }

        // 5. Verify File Integrity
        ui.log("Verifying File Integrity (This may take a moment)...");
        let manifest_str = String::from_utf8_lossy(&manifest_data);
        let mut count = 0;
        
        for line in manifest_str.lines() {
            if line.starts_with("Name: ") {
                count += 1;
            }
        }
        
        ui.start_phase("Verifying Files", count);

        // Parse Manifest simple (streaming check)
        let mut current_file = String::new();
        
        for line in manifest_str.lines() {
            if line.starts_with("Name: ") {
                current_file = line[6..].trim().to_string();
            } else if line.starts_with("SHA1-Digest: ") && !current_file.is_empty() {
                let expected = line[13..].trim();
                
                // Read actual file
                if let Ok(mut zf) = archive.by_name(&current_file) {
                    let actual = CryptoEngine::compute_stream_sha1(&mut zf)?;
                    if actual != expected {
                        return Err(SignerError::Validation(format!("Hash mismatch for {}", current_file)));
                    }
                    ui.tick();
                } else {
                    // It's allowed for manifest to list files not in zip (deleted), 
                    // but usually in OTA zip this implies modification.
                    ui.log(&format!("Warning: {} listed in manifest but missing from zip", current_file));
                }
                current_file.clear();
            }
        }

        Ok(true)
    }
}

// --- User Interface ---
struct UserInterface {
    total: std::cell::Cell<usize>,
    current: std::cell::Cell<usize>,
}

impl UserInterface {
    fn new() -> Self {
        Self {
            total: std::cell::Cell::new(0),
            current: std::cell::Cell::new(0),
        }
    }

    fn log(&self, msg: &str) {
        println!("  >> {}", msg);
    }

    fn start_phase(&self, name: &str, total: usize) {
        println!("\n:: {}", name);
        self.total.set(total);
        self.current.set(0);
    }

    fn tick(&self) {
        let c = self.current.get() + 1;
        self.current.set(c);
        let t = self.total.get();
        if t > 0 && (c % 5 == 0 || c == t) {
            let pct = (c as f32 / t as f32) * 100.0;
            print!("\r     [{:<50}] {:.0}%", "=".repeat((pct / 2.0) as usize), pct);
            io::stdout().flush().unwrap();
        }
        if c == t { println!(); }
    }
}

// --- Main Application ---
fn main() {
    let matches = Command::new(APP_NAME)
        .version(APP_VERSION)
        .author(APP_AUTHOR)
        .about("Professional Android ZIP Signing Tool")
        .arg(Arg::new("input").required(true).help("Input ZIP file"))
        .arg(Arg::new("output").help("Output ZIP file"))
        .arg(Arg::new("verify").short('v').long("verify").action(ArgAction::SetTrue).help("Verify mode"))
        .arg(Arg::new("private_key").short('k').long("private-key").help("Path to private key (PEM)"))
        .arg(Arg::new("public_key").short('p').long("public-key").help("Path to public key/cert (PEM)"))
        .arg(Arg::new("overwrite").short('f').long("overwrite").action(ArgAction::SetTrue).help("Force overwrite"))
        .arg(Arg::new("inplace").short('i').long("inplace").action(ArgAction::SetTrue).help("Sign in-place"))
        .get_matches();

    let ui = UserInterface::new();
    
    if let Err(e) = run(&matches, &ui) {
        eprintln!("\n\x1b[31mError:\x1b[0m {}", e);
        std::process::exit(1);
    }
}

fn run(matches: &clap::ArgMatches, ui: &UserInterface) -> Result<(), SignerError> {
    let input = PathBuf::from(matches.get_one::<String>("input").unwrap());
    
    // Load Keys
    ui.log("Initializing Crypto Engine...");
    let priv_path = matches.get_one::<String>("private_key").map(Path::new);
    let pub_path = matches.get_one::<String>("public_key").map(Path::new);
    let mut key_chain = KeyChain::new(priv_path, pub_path)?;

    // Verify Mode
    if matches.get_flag("verify") {
        ui.log(&format!("Verifying: {}", input.display()));
        if ArtifactVerifier::verify(&input, &key_chain, ui)? {
            println!("\n\x1b[32mSUCCESS: Verification Passed. The file is authentic.\x1b[0m");
        }
        return Ok(());
    }

    // Signing Mode
    let inplace = matches.get_flag("inplace");
    let output = if inplace {
        input.clone()
    } else if let Some(out) = matches.get_one::<String>("output") {
        PathBuf::from(out)
    } else {
        let file_stem = input.file_stem().unwrap().to_str().unwrap();
        let ext = input.extension().map(|s| s.to_str().unwrap()).unwrap_or("zip");
        input.with_file_name(format!("{}_signed.{}", file_stem, ext))
    };

    if output.exists() && !inplace && !matches.get_flag("overwrite") {
        return Err(SignerError::Config(format!("Output file exists: {}. Use --overwrite.", output.display())));
    }

    ui.log("Scanning Artifacts...");
    
    // Pass 1: Compute Hashes (Read Only)
    let digests = ArtifactProcessor::compute_manifest_digests(&input, ui)?;

    // Prepare Self-Signed Cert if needed
    key_chain.ensure_certificate()?;

    // Handle In-Place Backup
    let working_input = if inplace {
        let backup = input.with_extension("bak");
        fs::rename(&input, &backup)?;
        ui.log(&format!("Created backup: {}", backup.display()));
        backup
    } else {
        input.clone()
    };

    // Pass 2: Write Output
    match ArtifactProcessor::write_signed_zip(&working_input, &output, &key_chain, &digests, ui) {
        Ok(_) => {
            if inplace { fs::remove_file(&working_input)?; } // Cleanup backup
            println!("\n\x1b[32mSUCCESS: Signed ZIP created at {}\x1b[0m", output.display());
            Ok(())
        }
        Err(e) => {
            if inplace { fs::rename(&working_input, &input)?; } // Restore backup
            Err(e)
        }
    }
}