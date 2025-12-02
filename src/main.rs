use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use clap::{Arg, ArgAction, Command};
use openssl::{
    hash::MessageDigest,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    rsa::Padding,
    sign::{Signer, Verifier},
    ssl::SslMethod,
    x509::{X509, X509Name},
};
use sha1::{Digest, Sha1};
use zip::{
    read::ZipArchive,
    write::{FileOptions, ZipWriter},
    CompressionMethod, DateTime, ZipArchiveBuilder,
};

const MANIFEST_NAME: &str = "META-INF/MANIFEST.MF";
const CERT_SF_NAME: &str = "META-INF/CERT.SF";
const CERT_RSA_NAME: &str = "META-INF/CERT.RSA";
const STRIP_PATTERN: &str = r"^META-INF/(.*)\.(SF|RSA|DSA)$";

// Android-compatible signature block templates
const SIG_BLOCK_TEMPLATE_MEDIA: &[u8] = include_bytes!("templates/media.sbt");
const SIG_BLOCK_TEMPLATE_PLATFORM: &[u8] = include_bytes!("templates/platform.sbt");
const SIG_BLOCK_TEMPLATE_SHARED: &[u8] = include_bytes!("templates/shared.sbt");
const SIG_BLOCK_TEMPLATE_TESTKEY: &[u8] = include_bytes!("templates/testkey.sbt");

#[derive(Debug, Clone, PartialEq)]
struct KeySet {
    name: String,
    private_key: PKey<Private>,
    certificate: X509,
    sig_block_template: Vec<u8>,
}

enum KeyMode {
    AutoTestKey,
    AutoNone,
    Auto,
    Media,
    Platform,
    Shared,
    TestKey,
    None,
    Custom(String),
}

impl FromStr for KeyMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto-testkey" => Ok(KeyMode::AutoTestKey),
            "auto-none" => Ok(KeyMode::AutoNone),
            "auto" => Ok(KeyMode::Auto),
            "media" => Ok(KeyMode::Media),
            "platform" => Ok(KeyMode::Platform),
            "shared" => Ok(KeyMode::Shared),
            "testkey" | "test-key" => Ok(KeyMode::TestKey),
            "none" => Ok(KeyMode::None),
            _ => Ok(KeyMode::Custom(s.to_string())),
        }
    }
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

    fn cancel(&mut self) {
        self.canceled = true;
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
    let matches = Command::new("zipsigner")
        .version("1.1")
        .author("Android Open Source Project")
        .about("Signs ZIP/APK files in Android-compatible format")
        .arg(Arg::new("input")
            .help("Input ZIP/APK file to sign")
            .required(true)
            .index(1))
        .arg(Arg::new("output")
            .help("Output signed ZIP/APK file (optional)")
            .index(2))
        .arg(Arg::new("keymode")
            .short('k')
            .long("keymode")
            .value_name("MODE")
            .default_value("auto-testkey")
            .help("Key mode: auto-testkey, auto-none, auto, media, platform, shared, testkey, none"))
        .arg(Arg::new("keystore")
            .short('s')
            .long("keystore")
            .value_name("FILE")
            .help("Path to PKCS#12 keystore file"))
        .arg(Arg::new("keystore_pass")
            .short('p')
            .long("keystore-pass")
            .value_name("PASSWORD")
            .help("Keystore password"))
        .arg(Arg::new("key_alias")
            .short('a')
            .long("key-alias")
            .value_name("ALIAS")
            .help("Key alias in keystore"))
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
    let keymode_str = matches.get_one::<String>("keymode").unwrap();
    let keymode = KeyMode::from_str(keymode_str)?;
    let overwrite = matches.get_flag("overwrite");
    let inplace = matches.get_flag("inplace");

    // Validate input file
    if !input_path.exists() {
        return Err(format!("Input file '{}' does not exist", input_path.display()).into());
    }
    if input_path.is_dir() {
        return Err(format!("'{}' is a directory, not a file", input_path.display()).into());
    }

    // Determine output path
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

    // Initialize progress tracking
    let mut progress = ProgressState::new();

    // Load keys based on mode
    let mut key_set = None;
    if let Some(keystore_path) = matches.get_one::<String>("keystore") {
        let keystore_pass = matches
            .get_one::<String>("keystore_pass")
            .map(|s| s.as_str())
            .unwrap_or("");
        let key_alias = matches
            .get_one::<String>("key_alias")
            .map(|s| s.as_str())
            .unwrap_or("");

        progress.report("Loading certificate and private key from keystore");
        key_set = Some(load_keys_from_keystore(
            Path::new(keystore_path),
            keystore_pass,
            key_alias,
        )?);
    } else if !matches!(keymode, KeyMode::None) {
        progress.report("Determining signing key");
        let archive = ZipArchive::new(File::open(input_path)?)?;
        let entries = load_zip_entries(&archive)?;
        key_set = determine_key_set(&keymode, &entries, &mut progress)?;
    }

    // Handle in-place mode with backup
    if inplace {
        let backup_path = generate_backup_path(input_path)?;
        fs::rename(input_path, &backup_path)?;
        progress.report(&format!(
            "Original file backed up to: {}",
            backup_path.display()
        ));
        sign_zip_file(&backup_path, &output_path, key_set.as_ref(), &mut progress)?;
        fs::remove_file(backup_path)?;
    } else {
        sign_zip_file(input_path, &output_path, key_set.as_ref(), &mut progress)?;
    }

    progress.report(&format!("Signed ZIP created at: {}", output_path.display()));
    Ok(())
}

fn determine_key_set(
    keymode: &KeyMode,
    entries: &BTreeMap<String, Vec<u8>>,
    progress: &mut ProgressState,
) -> Result<Option<KeySet>, Box<dyn std::error::Error>> {
    if matches!(keymode, KeyMode::None) {
        return Ok(None);
    }

    if !keymode.to_string().starts_with("auto") {
        return Ok(Some(load_builtin_key_set(&keymode.to_string())?));
    }

    // Auto-detect key from existing signature
    if let Some((key_name, _)) = auto_detect_key(entries)? {
        progress.report(&format!("Auto-detected key: {}", key_name));
        return Ok(Some(load_builtin_key_set(&key_name)?));
    }

    match keymode {
        KeyMode::AutoTestKey => {
            progress.report("Falling back to testkey");
            Ok(Some(load_builtin_key_set("testkey")?))
        }
        KeyMode::AutoNone => {
            progress.report("No key detected, copying without signing");
            Ok(None)
        }
        _ => Err("Unable to determine signing key automatically".into()),
    }
}

fn auto_detect_key(
    entries: &BTreeMap<String, Vec<u8>>,
) -> Result<Option<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
    for (name, data) in entries {
        if name.starts_with("META-INF/") && name.ends_with(".RSA") && data.len() >= 1458 {
            // Compute MD5 of first 1458 bytes of signature block
            let hash = md5::compute(&data[..1458]);
            let md5_str = format!("{:x}", hash);

            let key_map = [
                ("aa9852bc5a53272ac8031d49b65e4b0f", "media"),
                ("e60418c4b638f20d0721e115674ca11f", "platform"),
                ("3e24e49741b60c215c010dc6048fca7d", "shared"),
                ("dab2cead827ef5313f28e22b6fa8479f", "testkey"),
            ];

            if let Some((_, key_name)) = key_map.iter().find(|(hash, _)| *hash == md5_str) {
                return Ok(Some((key_name.to_string(), data.clone())));
            }
        }
    }
    Ok(None)
}

fn load_builtin_key_set(name: &str) -> Result<KeySet, Box<dyn std::error::Error>> {
    let (private_key_pem, cert_pem, sig_block_template) = match name {
        "media" => (
            include_str!("keys/media.pk8"),
            include_str!("keys/media.x509.pem"),
            SIG_BLOCK_TEMPLATE_MEDIA.to_vec(),
        ),
        "platform" => (
            include_str!("keys/platform.pk8"),
            include_str!("keys/platform.x509.pem"),
            SIG_BLOCK_TEMPLATE_PLATFORM.to_vec(),
        ),
        "shared" => (
            include_str!("keys/shared.pk8"),
            include_str!("keys/shared.x509.pem"),
            SIG_BLOCK_TEMPLATE_SHARED.to_vec(),
        ),
        "testkey" => (
            include_str!("keys/testkey.pk8"),
            include_str!("keys/testkey.x509.pem"),
            SIG_BLOCK_TEMPLATE_TESTKEY.to_vec(),
        ),
        _ => return Err(format!("Unknown built-in key: {}", name).into()),
    };

    let private_key = PKey::private_key_from_pem(private_key_pem.as_bytes())?;
    let certificate = X509::from_pem(cert_pem.as_bytes())?;

    Ok(KeySet {
        name: name.to_string(),
        private_key,
        certificate,
        sig_block_template,
    })
}

fn load_keys_from_keystore(
    path: &Path,
    password: &str,
    alias: &str,
) -> Result<KeySet, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut buffer = Vec::new();
    io::Read::read_to_end(&file, &mut buffer)?;

    let pkcs12 = Pkcs12::from_der(&buffer)?;
    let parsed = pkcs12.parse(password)?;

    // Find the certificate with matching alias or use the first one
    let certificate = if !alias.is_empty() {
        parsed
            .cert
            .iter()
            .find(|cert| {
                cert.subject_name().entries().any(|entry| {
                    let data = entry.data().as_utf8().unwrap_or_default();
                    data.contains(alias)
                })
            })
            .cloned()
            .ok_or_else(|| format!("Certificate with alias '{}' not found", alias))?
    } else {
        parsed
            .cert
            .first()
            .cloned()
            .ok_or("No certificates found in keystore")?
    };

    // For simplicity, we'll use a standard signature block template
    let sig_block_template = SIG_BLOCK_TEMPLATE_TESTKEY.to_vec();

    Ok(KeySet {
        name: "custom".to_string(),
        private_key: parsed.pkey,
        certificate,
        sig_block_template,
    })
}

fn sign_zip_file(
    input_path: &Path,
    output_path: &Path,
    key_set: Option<&KeySet>,
    progress: &mut ProgressState,
) -> Result<(), Box<dyn std::error::Error>> {
    // Open input ZIP archive
    let input_file = File::open(input_path)?;
    let mut archive = ZipArchive::new(io::BufReader::new(input_file))?;
    let entries = load_zip_entries(&archive)?;

    // Create output ZIP file
    let output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path)?;
    let mut zip_writer = ZipWriter::new(output_file);

    // If no key set, just copy all files
    if key_set.is_none() {
        progress.set_total(entries.len());
        for (name, data) in &entries {
            if progress.is_canceled() {
                return Err("Operation canceled".into());
            }

            progress.report(&format!("Copying: {}", name));
            let options = FileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);

            zip_writer.start_file(name, options)?;
            zip_writer.write_all(data)?;
            progress.update(1);
        }
        zip_writer.finish()?;
        return Ok(());
    }

    let key_set = key_set.unwrap();
    let timestamp = get_cert_timestamp(key_set)?;

    // Calculate total progress items
    let mut progress_items = 0;
    for name in entries.keys() {
        if should_sign_file(name) {
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

        if name == MANIFEST_NAME || name == CERT_SF_NAME || name == CERT_RSA_NAME {
            continue;
        }

        if regex::Regex::new(STRIP_PATTERN)?.is_match(name) {
            continue;
        }

        progress.report(&format!("Copying: {}", name));
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(timestamp)
            .unix_permissions(0o644);

        zip_writer.start_file(name, options)?;
        zip_writer.write_all(data)?;
        if should_sign_file(name) {
            progress.update(1);
        }
    }

    zip_writer.finish()?;
    Ok(())
}

fn load_zip_entries<R: Read + Seek>(
    archive: &ZipArchive<R>,
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

fn should_sign_file(name: &str) -> bool {
    let stripped_name = name.trim_start_matches('/').to_lowercase();
    let ext = Path::new(&stripped_name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    // Skip signing for certain file types
    if matches!(ext, "png" | "jpg" | "jpeg" | "webp" | "ttf" | "otf") {
        return false;
    }

    // Skip directories and signature files
    if stripped_name.ends_with('/')
        || stripped_name == MANIFEST_NAME
        || stripped_name == CERT_SF_NAME
        || stripped_name == CERT_RSA_NAME
        || regex::Regex::new(STRIP_PATTERN).unwrap().is_match(&stripped_name)
    {
        return false;
    }

    true
}

fn generate_manifest(entries: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut manifest = Vec::new();
    manifest.extend_from_slice(b"Manifest-Version: 1.0\r\n");
    manifest.extend_from_slice(b"Created-By: 1.0 (Android SignApk)\r\n\r\n");

    for (name, data) in entries {
        if !should_sign_file(name) {
            continue;
        }

        let mut hasher = Sha1::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let digest_base64 = base64_engine.encode(&digest);

        manifest.extend_from_slice(format!("Name: {}\r\n", name).as_bytes());
        manifest.extend_from_slice(
            format!("SHA1-Digest: {}\r\n\r\n", digest_base64).as_bytes(),
        );
    }

    Ok(manifest)
}

fn generate_cert_sf(manifest: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut cert_sf = Vec::new();
    cert_sf.extend_from_slice(b"Signature-Version: 1.0\r\n");
    cert_sf.extend_from_slice(b"Created-By: 1.0 (Android SignApk)\r\n");

    // Calculate digest of entire manifest
    let mut hasher = Sha1::new();
    hasher.update(manifest);
    let digest = hasher.finalize();
    let digest_base64 = base64_engine.encode(&digest);
    cert_sf.extend_from_slice(format!("\r\nSHA1-Digest-Manifest: {}\r\n\r\n", digest_base64).as_bytes());

    // Parse manifest entries and calculate digests for each
    let manifest_str = String::from_utf8_lossy(manifest);
    let mut current_entry = String::new();
    let mut in_attributes = false;

    for line in manifest_str.lines() {
        if line.is_empty() {
            if !current_entry.is_empty() && in_attributes {
                let mut hasher = Sha1::new();
                hasher.update(current_entry.as_bytes());
                let digest = hasher.finalize();
                let digest_base64 = base64_engine.encode(&digest);
                
                // Extract the name from the entry
                if let Some(name_line) = current_entry.lines().next() {
                    if name_line.starts_with("Name: ") {
                        let name = &name_line[6..];
                        cert_sf.extend_from_slice(format!("Name: {}\r\n", name).as_bytes());
                        cert_sf.extend_from_slice(format!("SHA1-Digest: {}\r\n\r\n", digest_base64).as_bytes());
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
    let mut signer = Signer::new(MessageDigest::sha1(), &key_set.private_key)?;
    signer.set_rsa_padding(Padding::PKCS1)?;
    signer.update(cert_sf)?;
    let signature = signer.sign_to_vec()?;

    // Create signature block using template
    let mut sig_block = key_set.sig_block_template.clone();
    
    // Replace placeholder with actual signature
    // Note: This is simplified - real implementation would parse the ASN.1 structure
    // and insert the signature at the correct position
    if sig_block.len() > 1458 && signature.len() == 128 {
        sig_block.truncate(1458);
        sig_block.extend_from_slice(&signature);
    } else {
        // Fallback to standard signature block generation
        sig_block = generate_standard_sig_block(key_set, &signature)?;
    }

    Ok(sig_block)
}

fn generate_standard_sig_block(
    key_set: &KeySet,
    signature: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // This is a simplified implementation
    // In a real production system, this would generate a proper PKCS#7 signature block
    let mut sig_block = Vec::new();
    
    // Add certificate
    let cert_der = key_set.certificate.to_der()?;
    sig_block.extend_from_slice(&cert_der);
    
    // Add signature
    sig_block.extend_from_slice(signature);
    
    Ok(sig_block)
}

fn get_cert_timestamp(key_set: &KeySet) -> Result<DateTime, Box<dyn std::error::Error>> {
    // Use certificate's not-before time + 1 hour
    let not_before = key_set.certificate.not_before().to_owned();
    let timestamp = not_before.add(3600)?;
    
    // Convert to zip DateTime format
    let year = timestamp.year() as u16;
    let month = timestamp.month() as u8;
    let day = timestamp.day() as u8;
    let hour = timestamp.hour() as u8;
    let minute = timestamp.minute() as u8;
    let second = timestamp.second() as u8;
    
    Ok(DateTime::from_date_and_time(year, month, day, hour, minute, second, 0)?)
}

fn write_zip_entry(
    zip_writer: &mut ZipWriter<File>,
    name: &str,
     &[u8],
    timestamp: DateTime,
    progress: &mut ProgressState,
) -> Result<(), Box<dyn std::error::Error>> {
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
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

impl ToString for KeyMode {
    fn to_string(&self) -> String {
        match self {
            KeyMode::AutoTestKey => "auto-testkey".to_string(),
            KeyMode::AutoNone => "auto-none".to_string(),
            KeyMode::Auto => "auto".to_string(),
            KeyMode::Media => "media".to_string(),
            KeyMode::Platform => "platform".to_string(),
            KeyMode::Shared => "shared".to_string(),
            KeyMode::TestKey => "testkey".to_string(),
            KeyMode::None => "none".to_string(),
            KeyMode::Custom(s) => s.clone(),
        }
    }
}