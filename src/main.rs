use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Seek, Write},
    path::{Path, PathBuf},
    str,
    time::{SystemTime, UNIX_EPOCH},
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

const MANIFEST_NAME: &str = "META-INF/MANIFEST.MF";
const CERT_SF_NAME: &str = "META-INF/CERT.SF";
const CERT_RSA_NAME: &str = "META-INF/CERT.RSA";

// Default keys embedded from the certs directory
const DEFAULT_PRIVATE_KEY: &str = include_str!("../certs/private_key.pem");
const DEFAULT_PUBLIC_KEY: &str = include_str!("../certs/public_key.pem");

#[derive(Debug, Clone)]
struct KeySet {
    private_key: Option<PKey<Private>>,
    certificate: Option<X509>,
}

struct ProgressState {
    total_items: usize,
    current_item: usize,
    canceled: bool,
}

impl ProgressState {
    fn new() -> Self {
        Self {
            total_items: 0,
            current_item: 0,
            canceled: false,
        }
    }

    fn is_canceled(&self) -> bool {
        self.canceled
    }

    fn update(&mut self, increment: usize) -> bool {
        self.current_item += increment;
        !self.canceled
    }

    fn set_total(&mut self, total: usize) {
        self.total_items = total;
    }

    fn report(&self, message: &str) {
        if self.total_items > 0 {
            let percent = (self.current_item as f32 / self.total_items as f32) * 100.0;
            eprintln!("[{:>3.0}%] {}", percent, message);
        } else {
            eprintln!("{}", message);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("zipsignerust")
        .version("1.0")
        .author("Tiash H Kabir (@MrCarb0n)")
        .about("Signs and verifies Android flashable ZIP files with RSA signatures")
        .arg(Arg::new("input")
            .help("Input Android flashable ZIP file to sign or verify")
            .required(true)
            .index(1))
        .arg(Arg::new("output")
            .help("Output signed Android flashable ZIP file (optional)")
            .index(2))
        .arg(Arg::new("verify")
            .short('v')
            .long("verify")
            .action(ArgAction::SetTrue)
            .help("Verify the signature of the input ZIP file instead of signing"))
        .arg(Arg::new("private_key")
            .short('k')
            .long("private-key")
            .value_name("PRIVATE_KEY")
            .help("Path to private key file (PEM format) [optional for signing]"))
        .arg(Arg::new("public_key")
            .short('p')
            .long("public-key")
            .value_name("PUBLIC_KEY")
            .help("Path to public key file (PEM format) [optional for verification]"))
        .arg(Arg::new("overwrite")
            .short('f')
            .long("overwrite")
            .action(ArgAction::SetTrue)
            .help("Overwrite existing output file"))
        .arg(Arg::new("inplace")
            .short('i')
            .long("inplace")
            .action(ArgAction::SetTrue)
            .help("Sign in-place (backup original and overwrite input)"))
        .get_matches();

    let input_path = Path::new(matches.get_one::<String>("input").unwrap());
    let private_key_path = matches.get_one::<String>("private_key").map(Path::new);
    let public_key_path = matches.get_one::<String>("public_key").map(Path::new);
    let verify = matches.get_flag("verify");
    let overwrite = matches.get_flag("overwrite");
    let inplace = matches.get_flag("inplace");

    // Validate input file
    if !input_path.exists() {
        return Err(format!("Input file '{}' does not exist", input_path.display()).into());
    }
    if input_path.is_dir() {
        return Err(format!("'{}' is a directory, not a file", input_path.display()).into());
    }

    // Initialize progress tracking
    let mut progress = ProgressState::new();
    progress.report("Loading keys");

    if verify {
        // Verification mode
        let public_key = if let Some(pub_path) = public_key_path {
            progress.report(&format!("Using external public key: {}", pub_path.display()));
            load_public_key_from_file(pub_path)?
        } else {
            progress.report("Using embedded default public key");
            load_embedded_public_key()?
        };

        progress.report(&format!("Verifying signatures in: {}", input_path.display()));
        let result = verify_android_zip(input_path, &public_key, &mut progress)?;
        
        if result {
            progress.report("Verification successful: ZIP file signatures are valid");
            println!("ZIP file verification passed");
        } else {
            progress.report("Verification failed: ZIP file signatures are invalid");
            println!("ZIP file verification failed");
            std::process::exit(1);
        }
        
        return Ok(());
    }

    // Determine output path for signing
    let output_path = if inplace {
        input_path.to_path_buf()
    } else if let Some(out) = matches.get_one::<String>("output") {
        PathBuf::from(out)
    } else {
        get_default_output_path(input_path)?
    };

    // Handle overwrite protection
    if output_path.exists() && !overwrite && !inplace {
        return Err(format!(
            "Output file '{}' exists. Use --overwrite to force.",
            output_path.display()
        )
        .into());
    }

    // Load keys for signing
    let private_key = if let Some(priv_path) = private_key_path {
        progress.report(&format!("Using external private key: {}", priv_path.display()));
        Some(load_private_key_from_file(priv_path)?)
    } else {
        progress.report("Using embedded default private key");
        Some(load_embedded_private_key()?)
    };

    let public_key = if let Some(pub_path) = public_key_path {
        progress.report(&format!("Using external public key: {}", pub_path.display()));
        load_public_key_from_file(pub_path)?
    } else {
        progress.report("Using embedded default public key");
        load_embedded_public_key()?
    };

    // Create a self-signed certificate for the public key if needed
    let certificate = create_self_signed_certificate(&public_key)?;

    let key_set = KeySet {
        private_key,
        certificate: Some(certificate),
    };

    // Handle in-place mode with backup
    if inplace {
        let backup_path = generate_backup_path(input_path)?;
        fs::rename(input_path, &backup_path)?;
        progress.report(&format!(
            "Original file backed up to: {}",
            backup_path.display()
        ));
        sign_android_zip(&backup_path, &output_path, &key_set, &mut progress)?;
        fs::remove_file(backup_path)?;
    } else {
        sign_android_zip(input_path, &output_path, &key_set, &mut progress)?;
    }

    progress.report(&format!("Signed Android flashable ZIP created at: {}", output_path.display()));
    Ok(())
}

fn load_embedded_private_key() -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    PKey::private_key_from_pem(DEFAULT_PRIVATE_KEY.as_bytes())
        .map_err(|e| format!("Failed to load embedded private key: {}", e).into())
}

fn load_embedded_public_key() -> Result<PKey<Public>, Box<dyn std::error::Error>> {
    // Try as public key first
    if let Ok(key) = PKey::public_key_from_pem(DEFAULT_PUBLIC_KEY.as_bytes()) {
        return Ok(key);
    }
    // Fallback to X509 certificate
    let cert = X509::from_pem(DEFAULT_PUBLIC_KEY.as_bytes())
        .map_err(|e| format!("Failed to load embedded public key: {}", e))?;
    Ok(cert.public_key()?)
}

fn load_private_key_from_file(path: &Path) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;
    PKey::private_key_from_pem(data.as_bytes())
        .map_err(|e| format!("Failed to load private key from {}: {}", path.display(), e).into())
}

fn load_public_key_from_file(path: &Path) -> Result<PKey<Public>, Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;
    // Try as public key first
    if let Ok(key) = PKey::public_key_from_pem(data.as_bytes()) {
        return Ok(key);
    }
    // Fallback to X509 certificate
    let cert = X509::from_pem(data.as_bytes())
        .map_err(|e| format!("Failed to load public key from {}: {}", path.display(), e))?;
    Ok(cert.public_key()?)
}

fn create_self_signed_certificate(public_key: &PKey<Public>) -> Result<X509, Box<dyn std::error::Error>> {
    let mut name = X509Name::builder()?;
    name.append_entry_by_text("C", "US")?;
    name.append_entry_by_text("ST", "State")?;
    name.append_entry_by_text("L", "City")?;
    name.append_entry_by_text("O", "Organization")?;
    name.append_entry_by_text("OU", "zipsignerust")?;
    name.append_entry_by_text("CN", "Tiash H Kabir (@MrCarb0n)")?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?; // Version 3 (0-indexed)
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(public_key)?;
    
    // Set validity period: 10 years from now
    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(3650)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    
    // Sign the certificate with the private key (self-signed)
    let private_key = load_embedded_private_key()?;
    builder.sign(&private_key, MessageDigest::sha256())?;
    
    Ok(builder.build())
}

fn sign_android_zip(
    input_path: &Path,
    output_path: &Path,
    key_set: &KeySet,
    progress: &mut ProgressState,
) -> Result<(), Box<dyn std::error::Error>> {
    // Open input ZIP archive
    let input_file = File::open(input_path)?;
    let mut archive = ZipArchive::new(BufReader::new(input_file))?;
    let entries = load_zip_entries(&mut archive)?;

    // Create output ZIP file
    let output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;
    let mut zip_writer = ZipWriter::new(output_file);

    let timestamp = get_current_timestamp()?;

    // Calculate total progress items
    let mut progress_items = 0;
    for name in entries.keys() {
        if !name.starts_with("META-INF/") && !name.ends_with('/') {
            progress_items += 3; // MANIFEST entry, SF entry, copy file
        }
    }
    progress_items += 3; // MANIFEST.MF, CERT.SF, CERT.RSA
    progress.set_total(progress_items);

    // Generate and write MANIFEST.MF
    if progress.is_canceled() {
        return Err("Operation canceled".into());
    }
    progress.report("Generating MANIFEST.MF");
    let manifest = generate_manifest(&entries)?;
    write_zip_entry(
        &mut zip_writer,
        MANIFEST_NAME,
        &manifest,
        timestamp,
        progress,
    )?;

    // Generate and write CERT.SF
    if progress.is_canceled() {
        return Err("Operation canceled".into());
    }
    progress.report("Generating CERT.SF");
    let cert_sf = generate_cert_sf(&manifest)?;
    write_zip_entry(
        &mut zip_writer,
        CERT_SF_NAME,
        &cert_sf,
        timestamp,
        progress,
    )?;

    // Generate and write CERT.RSA
    if progress.is_canceled() {
        return Err("Operation canceled".into());
    }
    progress.report("Generating CERT.RSA signature block");
    let cert_rsa = generate_cert_rsa(key_set, &cert_sf)?;
    write_zip_entry(
        &mut zip_writer,
        CERT_RSA_NAME,
        &cert_rsa,
        timestamp,
        progress,
    )?;

    // Copy all other files
    for (name, data) in &entries {
        if progress.is_canceled() {
            return Err("Operation canceled".into());
        }

        // Skip existing signature files and directories
        if name.starts_with("META-INF/") && 
           (name.ends_with(".SF") || name.ends_with(".RSA") || name.ends_with(".DSA") || name.ends_with(".PK7")) {
            continue;
        }

        progress.report(&format!("Copying: {}", name));
        let options = FileOptions::default()
            .compression_method(if !data.is_empty() { CompressionMethod::Deflated } else { CompressionMethod::Stored })
            .last_modified_time(timestamp)
            .unix_permissions(0o755); // Android flashable ZIPs typically use 755 permissions

        zip_writer.start_file(name, options)?;
        zip_writer.write_all(data)?;
        
        if !name.starts_with("META-INF/") && !name.ends_with('/') {
            progress.update(1);
        }
    }

    zip_writer.finish()?;
    Ok(())
}

fn verify_android_zip(
    input_path: &Path,
    public_key: &PKey<Public>,
    progress: &mut ProgressState,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Open input ZIP archive
    let input_file = File::open(input_path)?;
    let mut archive = ZipArchive::new(BufReader::new(input_file))?;
    let entries = load_zip_entries(&mut archive)?;

    // Check if signature files exist
    if !entries.contains_key(MANIFEST_NAME) {
        eprintln!("Error: {} not found in ZIP file", MANIFEST_NAME);
        return Ok(false);
    }
    if !entries.contains_key(CERT_SF_NAME) {
        eprintln!("Error: {} not found in ZIP file", CERT_SF_NAME);
        return Ok(false);
    }
    if !entries.contains_key(CERT_RSA_NAME) {
        eprintln!("Error: {} not found in ZIP file", CERT_RSA_NAME);
        return Ok(false);
    }

    // Verify CERT.RSA signature against CERT.SF
    progress.report("Verifying CERT.RSA signature");
    let cert_sf = entries.get(CERT_SF_NAME).unwrap();
    let cert_rsa = entries.get(CERT_RSA_NAME).unwrap();
    
    if !verify_signature(public_key, cert_sf, cert_rsa) {
        eprintln!("Error: CERT.RSA signature verification failed");
        return Ok(false);
    }

    // Verify MANIFEST.MF entries against actual file contents
    progress.report("Verifying file signatures");
    let manifest = entries.get(MANIFEST_NAME).unwrap();
    let manifest_entries = parse_manifest(manifest)?;
    
    for (name, expected_digest) in manifest_entries {
        if name == "META-INF/MANIFEST.MF" || name.starts_with("META-INF/") {
            continue;
        }
        
        if let Some(file_data) = entries.get(&name) {
            let actual_digest = compute_sha1_digest(file_data);
            if actual_digest != expected_digest {
                eprintln!("Error: File '{}' has invalid digest", name);
                eprintln!("Expected: {}", expected_digest);
                eprintln!("Actual:   {}", actual_digest);
                return Ok(false);
            }
        } else {
            eprintln!("Error: File '{}' not found in ZIP but listed in manifest", name);
            return Ok(false);
        }
    }

    Ok(true)
}

fn verify_signature(
    public_key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
) -> bool {
    match Verifier::new(MessageDigest::sha1(), public_key) {
        Ok(mut verifier) => {
            if let Err(e) = verifier.set_rsa_padding(Padding::PKCS1) {
                eprintln!("Error setting RSA padding: {}", e);
                return false;
            }
            
            match verifier.update(data) {
                Ok(_) => match verifier.verify(signature) {
                    Ok(valid) => valid,
                    Err(e) => {
                        eprintln!("Error verifying signature: {}", e);
                        false
                    }
                },
                Err(e) => {
                    eprintln!("Error updating verifier: {}", e);
                    false
                }
            }
        }
        Err(e) => {
            eprintln!("Error creating verifier: {}", e);
            false
        }
    }
}

fn parse_manifest(manifest: &[u8]) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let manifest_str = String::from_utf8_lossy(manifest);
    let mut entries = BTreeMap::new();
    let mut current_name = None;
    let mut current_digest = None;

    for line in manifest_str.lines() {
        if line.starts_with("Name: ") {
            current_name = Some(line[6..].trim().to_string());
        } else if line.starts_with("SHA1-Digest: ") {
            current_digest = Some(line[13..].trim().to_string());
        } else if line.is_empty() && current_name.is_some() && current_digest.is_some() {
            entries.insert(
                current_name.take().unwrap(),
                current_digest.take().unwrap(),
            );
        }
    }

    // Handle the last entry if there's no trailing empty line
    if let (Some(name), Some(digest)) = (current_name, current_digest) {
        entries.insert(name, digest);
    }

    Ok(entries)
}

fn compute_sha1_digest(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let digest = hasher.finalize();
    base64_engine.encode(&digest)
}

fn load_zip_entries<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    let mut entries = BTreeMap::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        entries.insert(name, data);
    }

    Ok(entries)
}

fn generate_manifest(entries: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut manifest = Vec::new();
    manifest.extend_from_slice(b"Manifest-Version: 1.0\r\n");
    manifest.extend_from_slice(b"Created-By: 1.0 (zipsignerust)\r\n\r\n");

    for (name, data) in entries {
        // Skip META-INF files and directories
        if name.starts_with("META-INF/") || name.ends_with('/') {
            continue;
        }

        let digest = compute_sha1_digest(data);
        manifest.extend_from_slice(format!("Name: {}\r\n", name).as_bytes());
        manifest.extend_from_slice(
            format!("SHA1-Digest: {}\r\n\r\n", digest).as_bytes(),
        );
    }

    Ok(manifest)
}

fn generate_cert_sf(manifest: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut cert_sf = Vec::new();
    cert_sf.extend_from_slice(b"Signature-Version: 1.0\r\n");
    cert_sf.extend_from_slice(b"Created-By: 1.0 (zipsignerust)\r\n");

    // Calculate digest of entire manifest
    let digest = compute_sha1_digest(manifest);
    cert_sf.extend_from_slice(format!("\r\nSHA1-Digest-Manifest: {}\r\n\r\n", digest).as_bytes());

    // Parse manifest entries and calculate digests for each
    let manifest_str = String::from_utf8_lossy(manifest);
    let mut current_entry = String::new();
    let mut in_attributes = false;

    for line in manifest_str.lines() {
        if line.is_empty() {
            if !current_entry.is_empty() && in_attributes {
                let digest = compute_sha1_digest(current_entry.as_bytes());
                
                // Extract the name from the entry
                if let Some(name_line) = current_entry.lines().next() {
                    if name_line.starts_with("Name: ") {
                        let name = &name_line[6..];
                        cert_sf.extend_from_slice(format!("Name: {}\r\n", name).as_bytes());
                        cert_sf.extend_from_slice(format!("SHA1-Digest: {}\r\n\r\n", digest).as_bytes());
                    }
                }
            }
            current_entry.clear();
            in_attributes = false;
            continue;
        }

        if current_entry.is_empty() && line.starts_with("Name: ") {
            in_attributes = true;
        }

        if in_attributes {
            current_entry.push_str(line);
            current_entry.push('\n');
        }
    }

    Ok(cert_sf)
}

fn generate_cert_rsa(key_set: &KeySet, cert_sf: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Sign the CERT.SF file
    if let Some(private_key) = &key_set.private_key {
        let mut signer = Signer::new(MessageDigest::sha1(), private_key)?;
        signer.set_rsa_padding(Padding::PKCS1)?;
        signer.update(cert_sf)?;
        let signature = signer.sign_to_vec()?;

        // Create PKCS#7 signature block
        let mut sig_block = Vec::new();
        
        // Add certificate
        if let Some(cert) = &key_set.certificate {
            let cert_der = cert.to_der()?;
            sig_block.extend_from_slice(&cert_der);
        }
        
        // Add signature
        sig_block.extend_from_slice(&signature);
        
        Ok(sig_block)
    } else {
        Err("No private key available for signing".into())
    }
}

fn get_current_timestamp() -> Result<DateTime, Box<dyn std::error::Error>> {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH)?;
    let secs = duration.as_secs();
    
    // Convert to date components
    let year = 1970 + (secs / (365 * 24 * 60 * 60));
    let day_of_year = (secs % (365 * 24 * 60 * 60)) as u32;
    let month = 1 + (day_of_year / 30) as u8;
    let day = 1 + (day_of_year % 30) as u8;
    let hour = 0;
    let minute = 0;
    let second = 0;
    
    DateTime::from_date_and_time(year as u16, month, day, hour, minute, second)
        .map_err(|_| "Invalid date/time calculation".into())
}

fn write_zip_entry(
    zip_writer: &mut ZipWriter<File>,
    name: &str,
    data: &[u8],
    timestamp: DateTime,
    progress: &mut ProgressState,
) -> Result<(), Box<dyn std::error::Error>> {
    let options = FileOptions::default()
        .compression_method(if !data.is_empty() { CompressionMethod::Deflated } else { CompressionMethod::Stored })
        .last_modified_time(timestamp)
        .unix_permissions(0o644);

    zip_writer.start_file(name, options)?;
    zip_writer.write_all(data)?;
    progress.update(1);
    Ok(())
}

fn get_default_output_path(input_path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let parent = input_path.parent().unwrap_or(Path::new("."));
    let stem = input_path
        .file_stem()
        .ok_or("Invalid input filename")?
        .to_str()
        .ok_or("Invalid filename encoding")?;
    let ext = input_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("zip");

    Ok(parent.join(format!("{}_signed.{}", stem, ext)))
}

fn generate_backup_path(input_path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let parent = input_path.parent().unwrap_or(Path::new("."));
    let stem = input_path
        .file_stem()
        .ok_or("Invalid input filename")?
        .to_str()
        .ok_or("Invalid filename encoding")?;
    let ext = input_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    // Generate timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();

    let backup_name = if ext.is_empty() {
        format!("{}_backup_{}", stem, timestamp)
    } else {
        format!("{}_backup_{}.{}", stem, timestamp, ext)
    };

    Ok(parent.join(backup_name))
}