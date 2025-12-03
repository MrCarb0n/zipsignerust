/*
 * Android ZIP Signer v2.2 (Pure CLI Edition)
 * Refactored for Speed, Low RAM usage, and Scriptability.
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
const BUFFER_SIZE: usize = 64 * 1024; // 64KB Buffer
const APP_NAME: &str = "zipsignerust";
const APP_VERSION: &str = "2.2.0";
const APP_AUTHOR: &str = "Tiash H Kabir (@MrCarb0n)";

const DEFAULT_PRIVATE_KEY: &str = include_str!("../certs/private_key.pem");
const DEFAULT_PUBLIC_KEY: &str = include_str!("../certs/public_key.pem");

// --- Error Handling ---
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
            SignerError::Zip(e) => write!(f, "ZIP Error: {}", e),
            SignerError::OpenSsl(e) => write!(f, "Crypto Error: {}", e),
            SignerError::Validation(s) => write!(f, "Validation Failed: {}", s),
            SignerError::Config(s) => write!(f, "Config Error: {}", s),
        }
    }
}
impl std::error::Error for SignerError {}
impl From<io::Error> for SignerError { fn from(e: io::Error) -> Self { Self::Io(e) } }
impl From<zip::result::ZipError> for SignerError { fn from(e: zip::result::ZipError) -> Self { Self::Zip(e) } }
impl From<openssl::error::ErrorStack> for SignerError { fn from(e: openssl::error::ErrorStack) -> Self { Self::OpenSsl(e) } }

// --- Main ---
fn main() {
    let matches = Command::new(APP_NAME)
        .version(APP_VERSION)
        .author(APP_AUTHOR)
        .about("High-performance Android ZIP Signer")
        .arg(Arg::new("input").required(true).help("Input ZIP file path"))
        .arg(Arg::new("output").help("Output ZIP file path"))
        .arg(Arg::new("verify").short('v').long("verify").action(ArgAction::SetTrue).help("Verify signature instead of signing"))
        .arg(Arg::new("private_key").short('k').long("private-key").help("Path to private key (PEM)"))
        .arg(Arg::new("public_key").short('p').long("public-key").help("Path to public key/cert (PEM)"))
        .arg(Arg::new("overwrite").short('f').long("overwrite").action(ArgAction::SetTrue).help("Force overwrite existing output"))
        .arg(Arg::new("inplace").short('i').long("inplace").action(ArgAction::SetTrue).help("Sign in-place (overwrites input)"))
        .get_matches();

    if let Err(e) = run(&matches) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(matches: &clap::ArgMatches) -> Result<(), SignerError> {
    let input_path = PathBuf::from(matches.get_one::<String>("input").unwrap());
    
    // 1. Load Keys
    println!(":: Loading keys...");
    let priv_path = matches.get_one::<String>("private_key").map(Path::new);
    let pub_path = matches.get_one::<String>("public_key").map(Path::new);
    let mut key_chain = KeyChain::new(priv_path, pub_path)?;

    // 2. Verify Mode
    if matches.get_flag("verify") {
        println!(":: Verifying: {}", input_path.display());
        if ArtifactVerifier::verify(&input_path, &key_chain)? {
            println!("SUCCESS: Verification Passed. The file is authentic.");
        }
        return Ok(());
    }

    // 3. Signing Mode
    let inplace = matches.get_flag("inplace");
    let output_path = if inplace {
        input_path.clone()
    } else if let Some(out) = matches.get_one::<String>("output") {
        PathBuf::from(out)
    } else {
        let stem = input_path.file_stem().unwrap().to_str().unwrap();
        input_path.with_file_name(format!("{}_signed.zip", stem))
    };

    if output_path.exists() && !inplace && !matches.get_flag("overwrite") {
        return Err(SignerError::Config(format!("Output file exists: {}. Use --overwrite.", output_path.display())));
    }

    // 4. Processing
    println!(":: Analyzing artifacts...");
    let digests = ArtifactProcessor::compute_manifest_digests(&input_path)?;

    key_chain.ensure_certificate()?;

    // Handle Backup for In-Place
    let working_input = if inplace {
        let backup = input_path.with_extension("bak");
        fs::rename(&input_path, &backup)?;
        println!(":: Backup created: {}", backup.display());
        backup
    } else {
        input_path.clone()
    };

    println!(":: Signing and packing...");
    match ArtifactProcessor::write_signed_zip(&working_input, &output_path, &key_chain, &digests) {
        Ok(_) => {
            if inplace { 
                // The .bak file is now intentionally kept after a successful in-place signing operation.
                // fs::remove_file(&working_input)?; 
                println!(":: Backup kept at: {}", working_input.display());
            }
            println!("SUCCESS: Signed ZIP created at {}", output_path.display());
            Ok(())
        }
        Err(e) => {
            if inplace { 
                // Restore the original file from the backup if signing failed
                fs::remove_file(&input_path)?; // Remove the partially written file
                fs::rename(&working_input, &input_path)?; 
                eprintln!(":: Restored original file due to error.");
            }
            Err(e)
        }
    }
}

// --- Components ---

struct CryptoEngine;
impl CryptoEngine {
    fn compute_sha1(data: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(data);
        base64_engine.encode(hasher.finalize())
    }
    fn compute_stream_sha1<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        let mut hasher = Sha1::new();
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 { break; }
            hasher.update(&buffer[..count]);
        }
        Ok(base64_engine.encode(hasher.finalize()))
    }
}

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
            Some(PKey::private_key_from_pem(DEFAULT_PRIVATE_KEY.as_bytes())?)
        };

        let (public_key, certificate) = if let Some(path) = pub_path {
            let data = fs::read(path)?;
            if let Ok(cert) = X509::from_pem(&data) {
                (Some(cert.public_key()?), Some(cert))
            } else {
                (Some(PKey::public_key_from_pem(&data)?), None)
            }
        } else {
            let cert = X509::from_pem(DEFAULT_PUBLIC_KEY.as_bytes())?;
            (Some(cert.public_key()?), Some(cert))
        };

        Ok(Self { private_key, public_key, certificate })
    }

    fn ensure_certificate(&mut self) -> Result<(), SignerError> {
        if self.certificate.is_none() {
            if let (Some(pk), Some(pubk)) = (&self.private_key, &self.public_key) {
                let mut builder = X509::builder()?;
                builder.set_version(2)?;
                
                let mut name_builder = X509Name::builder()?;
                name_builder.append_entry_by_text("CN", "Zipsigner Auto-Gen")?;
                let name = name_builder.build();
                
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

    fn get_timestamp_oracle(&self) -> DateTime {
        if let Some(cert) = &self.certificate {
            let time_str = cert.not_before().to_string();
            let re = Regex::new(r"([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})").unwrap();
            
            if let Some(caps) = re.captures(&time_str) {
                let month = match &caps[1] { "Jan"=>1,"Feb"=>2,"Mar"=>3,"Apr"=>4,"May"=>5,"Jun"=>6,"Jul"=>7,"Aug"=>8,"Sep"=>9,"Oct"=>10,"Nov"=>11,"Dec"=>12, _=>1 };
                let year = caps[6].parse::<u16>().unwrap_or(1980).max(1980);
                if let Ok(dt) = DateTime::from_date_and_time(year, month, caps[2].parse().unwrap_or(1), 0, 0, 0) {
                    return dt;
                }
            }
        }
        DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap()
    }
}

struct ArtifactProcessor;
impl ArtifactProcessor {
    fn compute_manifest_digests(path: &Path) -> Result<BTreeMap<String, String>, SignerError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(BufReader::new(file))?;
        let mut digests = BTreeMap::new();

        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i)?;
            let name = zip_file.name().to_string();
            if !name.ends_with('/') && !name.starts_with("META-INF/") {
                digests.insert(name, CryptoEngine::compute_stream_sha1(&mut zip_file)?);
            }
        }
        Ok(digests)
    }

    fn write_signed_zip(input: &Path, output: &Path, keys: &KeyChain, digests: &BTreeMap<String, String>) -> Result<(), SignerError> {
        let timestamp = keys.get_timestamp_oracle();
        let out_file = OpenOptions::new().create(true).write(true).truncate(true).open(output)?;
        let mut writer = ZipWriter::new(BufWriter::new(out_file));

        let manifest = Self::gen_manifest(digests);
        let sf = Self::gen_sf(&manifest);
        let rsa = Self::gen_rsa(keys, &sf)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &manifest, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa, timestamp)?;

        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;
        let mut buf = [0u8; BUFFER_SIZE];

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();
            
            if !name.starts_with("META-INF/") && !name.ends_with("MANIFEST.MF") && 
               !name.ends_with(".SF") && !name.ends_with(".RSA") {
                let options = FileOptions::default()
                    .compression_method(file.compression())
                    .last_modified_time(timestamp)
                    .unix_permissions(file.unix_mode().unwrap_or(0o644));
                
                writer.start_file(name, options)?;
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 { break; }
                    writer.write_all(&buf[..n])?;
                }
            }
        }
        writer.finish()?;
        Ok(())
    }

    fn write_entry(w: &mut ZipWriter<BufWriter<File>>, n: &str, d: &[u8], t: DateTime) -> Result<(), SignerError> {
        w.start_file(n, FileOptions::default().compression_method(CompressionMethod::Deflated).last_modified_time(t))?;
        w.write_all(d)?;
        Ok(())
    }

    fn gen_manifest(digests: &BTreeMap<String, String>) -> Vec<u8> {
        let mut out = format!("Manifest-Version: 1.0\r\nCreated-By: {}\r\n\r\n", APP_VERSION).into_bytes();
        for (n, h) in digests { out.extend(format!("Name: {}\r\nSHA1-Digest: {}\r\n\r\n", n, h).bytes()); }
        out
    }

    fn gen_sf(manifest: &[u8]) -> Vec<u8> {
        let mut out = format!("Signature-Version: 1.0\r\nCreated-By: {}\r\nSHA1-Digest-Manifest: {}\r\n\r\n", 
            APP_VERSION, CryptoEngine::compute_sha1(manifest)).into_bytes();
        
        let s = String::from_utf8_lossy(manifest);
        let mut buf = String::new();
        let mut in_ent = false;
        for line in s.lines() {
            if line.trim().is_empty() {
                if in_ent && !buf.is_empty() {
                    if let Some(n) = buf.lines().find(|l| l.starts_with("Name: ")) {
                        out.extend(format!("{}\r\nSHA1-Digest: {}\r\n\r\n", n, CryptoEngine::compute_sha1(buf.as_bytes())).bytes());
                    }
                }
                buf.clear(); in_ent = false; continue;
            }
            if !in_ent && line.starts_with("Name: ") { in_ent = true; }
            if in_ent { buf.push_str(line); buf.push('\n'); }
        }
        out
    }

    fn gen_rsa(keys: &KeyChain, sf: &[u8]) -> Result<Vec<u8>, SignerError> {
        let pk = keys.private_key.as_ref().ok_or(SignerError::Config("Private Key Missing".into()))?;
        let mut signer = Signer::new(MessageDigest::sha1(), pk)?;
        signer.set_rsa_padding(Padding::PKCS1)?;
        signer.update(sf)?;
        let sig = signer.sign_to_vec()?;
        
        let mut block = Vec::new();
        if let Some(cert) = &keys.certificate {
            block.extend_from_slice(&cert.to_der()?);
        }
        block.extend_from_slice(&sig);
        Ok(block)
    }
}

struct ArtifactVerifier;
impl ArtifactVerifier {
    fn verify(path: &Path, keys: &KeyChain) -> Result<bool, SignerError> {
        let pub_key = keys.public_key.as_ref().ok_or(SignerError::Config("Public Key Missing".into()))?;
        let mut archive = ZipArchive::new(File::open(path)?)?;
        
        // 1. Verify RSA Signature
        let mut rsa = Vec::new(); 
        if archive.by_name(CERT_RSA_NAME).is_err() { return Err(SignerError::Validation("No RSA Signature".into())); }
        archive.by_name(CERT_RSA_NAME)?.read_to_end(&mut rsa)?;
        
        let mut sf = Vec::new(); 
        if archive.by_name(CERT_SF_NAME).is_err() { return Err(SignerError::Validation("No SF File".into())); }
        archive.by_name(CERT_SF_NAME)?.read_to_end(&mut sf)?;
        
        let sig_len = pub_key.size();
        if rsa.len() < sig_len { return Err(SignerError::Validation("Corrupt RSA Block".into())); }
        let raw_sig = &rsa[rsa.len()-sig_len..];

        let mut v = Verifier::new(MessageDigest::sha1(), pub_key)?;
        v.set_rsa_padding(Padding::PKCS1)?;
        v.update(&sf)?;
        if !v.verify(raw_sig)? { return Err(SignerError::Validation("Invalid RSA Signature".into())); }

        // 2. Verify Manifest Hash
        let mut man = Vec::new(); 
        if archive.by_name(MANIFEST_NAME).is_err() { return Err(SignerError::Validation("No Manifest".into())); }
        archive.by_name(MANIFEST_NAME)?.read_to_end(&mut man)?;
        
        let man_hash = CryptoEngine::compute_sha1(&man);
        if !String::from_utf8_lossy(&sf).contains(&format!("SHA1-Digest-Manifest: {}", man_hash)) { 
            return Err(SignerError::Validation("SF-Manifest Mismatch".into())); 
        }

        // 3. Verify Files
        let s = String::from_utf8_lossy(&man);
        let mut cur = String::new();
        for line in s.lines() {
            if line.starts_with("Name: ") { cur = line[6..].trim().to_string(); }
            else if line.starts_with("SHA1-Digest: ") && !cur.is_empty() {
                let exp = line[13..].trim();
                if let Ok(mut zf) = archive.by_name(&cur) {
                    let act = CryptoEngine::compute_stream_sha1(&mut zf)?;
                    if act != exp { return Err(SignerError::Validation(format!("Hash Mismatch: {}", cur))); }
                }
                cur.clear();
            }
        }
        Ok(true)
    }
}