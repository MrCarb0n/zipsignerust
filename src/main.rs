/*
 * Android ZIP Signer v2.1 (Mobile UX Edition)
 * Features:
 * - Interactive TUI with File Picker
 * - Aesthetic Progress Bars (Indicatif)
 * - Strict Certificate Timestamp Inheritance
 */

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
    env,
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

// UI Libraries
use indicatif::{ProgressBar, ProgressStyle};
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Select, Input};
use colored::*;

// --- Constants & Config ---
const MANIFEST_NAME: &str = "META-INF/MANIFEST.MF";
const CERT_SF_NAME: &str = "META-INF/CERT.SF";
const CERT_RSA_NAME: &str = "META-INF/CERT.RSA";
const BUFFER_SIZE: usize = 64 * 1024;
const APP_VERSION: &str = "2.1.0";
const APP_NAME: &str = "zipsignerust";
const APP_AUTHOR: &str = "Tiash H Kabir (@MrCarb0n)";

const DEFAULT_PRIVATE_KEY: &str = include_str!("../certs/private_key.pem");
const DEFAULT_PUBLIC_KEY: &str = include_str!("../certs/public_key.pem");

// --- Entry Point ---
fn main() {
    // If args provided, run CLI mode. If not, run Interactive TUI.
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        run_cli_mode();
    } else {
        run_interactive_mode();
    }
}

// --- Interactive Mode (TUI) ---
fn run_interactive_mode() {
    let term = Term::stdout();
    term.clear_screen().ok();

    println!("{}", style(r#"
    ╔═══════════════════════════════════════╗
    ║      ANDROID ZIP SIGNER RUST          ║
    ║      v2.1.0 • @MrCarb0n               ║
    ╚═══════════════════════════════════════╝
    "#).cyan().bold());

    loop {
        let choices = &["📦  Sign a File", "🔍  Verify a File", "🚪  Exit"];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select an Action")
            .default(0)
            .items(choices)
            .interact()
            .unwrap_or(2);

        match selection {
            0 => interactive_sign(),
            1 => interactive_verify(),
            _ => break,
        }
    }
    println!("{}", "See you later, Space Cowboy. 🤠".dimmed());
}

fn interactive_sign() {
    println!("\n{}", "--- Select Input ZIP ---".yellow());
    let input_path = match file_picker(".") {
        Some(p) => p,
        None => return,
    };

    let default_name = input_path.file_stem().unwrap().to_str().unwrap();
    let default_output = format!("{}_signed.zip", default_name);

    let output_name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Output Filename")
        .default(default_output)
        .interact_text()
        .unwrap();
    
    let output_path = input_path.parent().unwrap().join(output_name);

    run_operation(true, &input_path, Some(&output_path));
}

fn interactive_verify() {
    println!("\n{}", "--- Select ZIP to Verify ---".yellow());
    if let Some(path) = file_picker(".") {
        run_operation(false, &path, None);
    }
}

/// A simple Terminal File Picker suitable for mobile usage
fn file_picker(start_dir: &str) -> Option<PathBuf> {
    let mut current_dir = fs::canonicalize(start_dir).unwrap_or_else(|_| PathBuf::from("."));
    
    loop {
        let mut entries: Vec<PathBuf> = fs::read_dir(&current_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect();
        
        // Sort: Directories first, then files
        entries.sort_by(|a, b| {
            let a_is_dir = a.is_dir();
            let b_is_dir = b.is_dir();
            if a_is_dir == b_is_dir {
                a.file_name().cmp(&b.file_name())
            } else {
                b_is_dir.cmp(&a_is_dir)
            }
        });

        // UI List preparation
        let mut choices = vec![".. (Go Up)".to_string()];
        let mut valid_indices = vec![];

        for (i, path) in entries.iter().enumerate() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if path.is_dir() {
                choices.push(format!("📂 {}", name));
                valid_indices.push(i);
            } else if name.ends_with(".zip") || name.ends_with(".jar") || name.ends_with(".apk") {
                choices.push(format!("📦 {}", name));
                valid_indices.push(i);
            }
        }

        // Add an option to cancel
        choices.push("❌ Cancel".to_string());

        // Display Menu
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("Browsing: {}", current_dir.display()))
            .default(0)
            .items(&choices)
            .max_length(10) // fit on mobile screen
            .interact()
            .unwrap_or(0);

        if selection == 0 {
            if let Some(parent) = current_dir.parent() {
                current_dir = parent.to_path_buf();
            }
            continue;
        }

        if selection == choices.len() - 1 {
            return None; // Canceled
        }

        let selected_path = &entries[valid_indices[selection - 1]];
        if selected_path.is_dir() {
            current_dir = selected_path.clone();
        } else {
            return Some(selected_path.clone());
        }
    }
}

// --- CLI Mode ---
fn run_cli_mode() {
    let matches = Command::new(APP_NAME)
        .version(APP_VERSION)
        .author(APP_AUTHOR)
        .arg(Arg::new("input").required(true).help("Input ZIP file"))
        .arg(Arg::new("output").help("Output ZIP file"))
        .arg(Arg::new("verify").short('v').long("verify").action(ArgAction::SetTrue))
        .arg(Arg::new("overwrite").short('f').long("overwrite").action(ArgAction::SetTrue))
        .arg(Arg::new("inplace").short('i').long("inplace").action(ArgAction::SetTrue))
        .get_matches();

    let input = PathBuf::from(matches.get_one::<String>("input").unwrap());
    let verify = matches.get_flag("verify");
    
    // Determine output path logic
    let output = if verify {
        None 
    } else if matches.get_flag("inplace") {
        Some(input.clone())
    } else if let Some(out) = matches.get_one::<String>("output") {
        Some(PathBuf::from(out))
    } else {
        let stem = input.file_stem().unwrap().to_str().unwrap();
        Some(input.with_file_name(format!("{}_signed.zip", stem)))
    };

    // FIX: Use as_deref() to convert Option<PathBuf> to Option<&Path>
    run_operation(!verify, &input, output.as_deref());
}

// --- Core Operation Wrapper ---
fn run_operation(signing: bool, input: &Path, output: Option<&Path>) {
    // Spinner setup
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}").unwrap());
    pb.enable_steady_tick(Duration::from_millis(100));

    // 1. Load Keys
    pb.set_message("Loading Cryptography Engine...");
    let key_chain = match KeyChain::new() {
        Ok(k) => k,
        Err(e) => { pb.finish_with_message(format!("❌ Key Error: {}", e)); return; }
    };

    // 2. Scan ZIP
    pb.set_message("Scanning Artifacts...");
    let digests = match ArtifactProcessor::compute_manifest_digests(input) {
        Ok(d) => d,
        Err(e) => { pb.finish_with_message(format!("❌ Read Error: {}", e)); return; }
    };

    if !signing {
        // VERIFY MODE
        pb.set_message("Verifying Signatures...");
        match ArtifactVerifier::verify(input, &key_chain, &digests) {
            Ok(true) => {
                pb.finish_and_clear();
                println!("{}", "✅ Verification Successful: The file is authentic.".green().bold());
            },
            Ok(false) => {
                pb.finish_and_clear();
                println!("{}", "❌ Verification Failed: Signature mismatch.".red().bold());
            },
            Err(e) => {
                pb.finish_with_message(format!("❌ Verify Error: {}", e));
            }
        }
        return;
    }

    // SIGN MODE
    let output_path = output.unwrap();
    pb.set_message("Generating Signatures...");
    
    // Switch to Bar for writing
    let write_pb = ProgressBar::new(digests.len() as u64);
    write_pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    match ArtifactProcessor::write_signed_zip(input, output_path, &key_chain, &digests, &write_pb) {
        Ok(_) => {
            write_pb.finish_and_clear();
            println!("\n{}", "✨ Operation Complete ✨".green().bold());
            println!("Output saved to: {}", style(output_path.display()).underlined());
        },
        Err(e) => {
            write_pb.finish_with_message(format!("❌ Write Error: {}", e));
        }
    }
}

// =========================================================
//  LOGIC IMPLEMENTATIONS (Optimized & Decoupled)
// =========================================================

#[derive(Debug)]
enum SignerError {
    Io(io::Error),
    Zip(zip::result::ZipError),
    OpenSsl(openssl::error::ErrorStack),
    Validation(String),
}
impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::Io(e) => write!(f, "IO: {}", e),
            SignerError::Zip(e) => write!(f, "ZIP: {}", e),
            SignerError::OpenSsl(e) => write!(f, "SSL: {}", e),
            SignerError::Validation(s) => write!(f, "Validation: {}", s),
        }
    }
}
impl std::error::Error for SignerError {}
impl From<io::Error> for SignerError { fn from(e: io::Error) -> Self { Self::Io(e) } }
impl From<zip::result::ZipError> for SignerError { fn from(e: zip::result::ZipError) -> Self { Self::Zip(e) } }
impl From<openssl::error::ErrorStack> for SignerError { fn from(e: openssl::error::ErrorStack) -> Self { Self::OpenSsl(e) } }

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
    private_key: PKey<Private>,
    public_key: PKey<Public>,
    certificate: X509,
}

impl KeyChain {
    fn new() -> Result<Self, SignerError> {
        // Load embedded defaults for reliability
        let private_key = PKey::private_key_from_pem(DEFAULT_PRIVATE_KEY.as_bytes())?;
        
        // Try to parse public key as Cert first (common case)
        let (public_key, certificate) = if let Ok(cert) = X509::from_pem(DEFAULT_PUBLIC_KEY.as_bytes()) {
            (cert.public_key()?, cert)
        } else {
            // Generate Self-Signed if only raw key provided
            let pub_key = PKey::public_key_from_pem(DEFAULT_PUBLIC_KEY.as_bytes())?;
            let mut builder = X509::builder()?;
            builder.set_version(2)?;
            let mut name = X509Name::builder()?;
            name.append_entry_by_text("CN", "Zipsigner Mobile")?;
            builder.set_subject_name(&name.build())?;
            builder.set_pubkey(&pub_key)?;
            builder.sign(&private_key, MessageDigest::sha256())?;
            (pub_key, builder.build())
        };

        Ok(Self { private_key, public_key, certificate })
    }

    fn get_timestamp_oracle(&self) -> DateTime {
        let time_str = self.certificate.not_before().to_string();
        let re = Regex::new(r"([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})").unwrap();
        
        if let Some(caps) = re.captures(&time_str) {
            let month = match &caps[1] { "Jan"=>1,"Feb"=>2,"Mar"=>3,"Apr"=>4,"May"=>5,"Jun"=>6,"Jul"=>7,"Aug"=>8,"Sep"=>9,"Oct"=>10,"Nov"=>11,"Dec"=>12, _=>1 };
            let year = caps[6].parse::<u16>().unwrap_or(1980).max(1980);
            return DateTime::from_date_and_time(year, month, caps[2].parse().unwrap_or(1), 0,0,0).unwrap_or(DateTime::default());
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

    fn write_signed_zip(input: &Path, output: &Path, keys: &KeyChain, digests: &BTreeMap<String, String>, pb: &ProgressBar) -> Result<(), SignerError> {
        let timestamp = keys.get_timestamp_oracle();
        let out_file = OpenOptions::new().create(true).write(true).truncate(true).open(output)?;
        let mut writer = ZipWriter::new(BufWriter::new(out_file));

        // Signatures
        let manifest = Self::gen_manifest(digests);
        let sf = Self::gen_sf(&manifest);
        let rsa = Self::gen_rsa(keys, &sf)?;

        Self::write_entry(&mut writer, MANIFEST_NAME, &manifest, timestamp)?;
        Self::write_entry(&mut writer, CERT_SF_NAME, &sf, timestamp)?;
        Self::write_entry(&mut writer, CERT_RSA_NAME, &rsa, timestamp)?;

        // Content Copy
        let mut archive = ZipArchive::new(BufReader::new(File::open(input)?))?;
        let mut buf = [0u8; BUFFER_SIZE];

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();
            
            if !name.starts_with("META-INF/") && !name.ends_with("MANIFEST.MF") {
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
                pb.inc(1);
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
        let mut signer = Signer::new(MessageDigest::sha1(), &keys.private_key)?;
        signer.set_rsa_padding(Padding::PKCS1)?;
        signer.update(sf)?;
        let sig = signer.sign_to_vec()?;
        let mut block = keys.certificate.to_der()?;
        block.extend_from_slice(&sig);
        Ok(block)
    }
}

struct ArtifactVerifier;
impl ArtifactVerifier {
    fn verify(path: &Path, keys: &KeyChain, digests: &BTreeMap<String, String>) -> Result<bool, SignerError> {
        let mut archive = ZipArchive::new(File::open(path)?)?;
        
        // 1. Verify RSA Signature
        let mut rsa = Vec::new(); archive.by_name(CERT_RSA_NAME)?.read_to_end(&mut rsa)?;
        let mut sf = Vec::new(); archive.by_name(CERT_SF_NAME)?.read_to_end(&mut sf)?;
        
        let sig_len = keys.public_key.size();
        if rsa.len() < sig_len { return Err(SignerError::Validation("Corrupt RSA".into())); }
        let raw_sig = &rsa[rsa.len()-sig_len..];

        let mut v = Verifier::new(MessageDigest::sha1(), &keys.public_key)?;
        v.set_rsa_padding(Padding::PKCS1)?;
        v.update(&sf)?;
        if !v.verify(raw_sig)? { return Ok(false); }

        // 2. Verify Manifest Hash
        let mut man = Vec::new(); archive.by_name(MANIFEST_NAME)?.read_to_end(&mut man)?;
        let man_hash = CryptoEngine::compute_sha1(&man);
        if !String::from_utf8_lossy(&sf).contains(&format!("SHA1-Digest-Manifest: {}", man_hash)) { return Ok(false); }

        // 3. Verify Files (Fast check via pre-computed digests)
        let s = String::from_utf8_lossy(&man);
        let mut cur = String::new();
        for line in s.lines() {
            if line.starts_with("Name: ") { cur = line[6..].trim().to_string(); }
            else if line.starts_with("SHA1-Digest: ") && !cur.is_empty() {
                let exp = line[13..].trim();
                if let Some(act) = digests.get(&cur) {
                    if act != exp { return Ok(false); }
                }
            }
        }
        Ok(true)
    }
}
