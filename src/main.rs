use std::{
    env,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use clap::{Arg, Command};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};
use rand::{distributions::Alphanumeric, Rng};
use zip::{read::ZipArchive, write::FileOptions, CompressionMethod, ZipWriter};

const DEFAULT_PRIVATE_KEY: &str = include_str!("../certs/private_key.pem");

fn main() -> Result<(), String> {
    let matches = Command::new("zipsigner")
        .version("1.0")
        .author("Your Name")
        .about("Signs ZIP files with RSA private key")
        .arg(Arg::new("input")
            .help("Input ZIP file to sign")
            .required(true)
            .index(1))
        .arg(Arg::new("output")
            .help("Output signed ZIP file (optional)")
            .index(2))
        .arg(Arg::new("external-key")
            .short('k')
            .long("external-key")
            .value_name("FILE")
            .help("Path to external private key file (PEM format)"))
        .arg(Arg::new("overwrite")
            .short('f')
            .long("overwrite")
            .help("Overwrite existing output file"))
        .arg(Arg::new("inplace")
            .short('i')
            .long("inplace")
            .help("Sign in-place (backup original and overwrite input)"))
        .get_matches();

    let input_path = Path::new(matches.value_of("input").unwrap());
    let external_key_path = matches.value_of("external-key").map(Path::new);
    let overwrite = matches.is_present("overwrite");
    let inplace = matches.is_present("inplace");

    // Validate input file exists
    if !input_path.exists() {
        return Err(format!("Input file '{}' does not exist", input_path.display()));
    }

    if input_path.is_dir() {
        return Err(format!("'{}' is a directory, not a file", input_path.display()));
    }

    // Determine output path
    let output_path = if inplace {
        // In-place mode uses input path as output
        input_path.to_path_buf()
    } else if let Some(out) = matches.value_of("output") {
        PathBuf::from(out)
    } else {
        // Auto-generate output name if not specified
        get_default_output_path(input_path)
    };

    // Handle external key or use embedded
    let private_key = if let Some(key_path) = external_key_path {
        load_private_key_from_file(key_path)?
    } else {
        load_embedded_private_key()?
    };

    // In-place mode requires special handling
    if inplace {
        handle_inplace_mode(input_path, &output_path, &private_key)?
    } else {
        // Standard mode with overwrite check
        if output_path.exists() && !overwrite {
            return Err(format!(
                "Output file '{}' exists. Use --overwrite to force.",
                output_path.display()
            ));
        }
        sign_zip_file(input_path, &output_path, &private_key)?;
        println!("Signed ZIP created at: {}", output_path.display());
    }

    Ok(())
}

fn handle_inplace_mode(
    input_path: &Path,
    output_path: &Path,
    private_key: &PKey<openssl::pkey::Private>,
) -> Result<(), String> {
    // Generate backup path with timestamp
    let backup_path = generate_backup_path(input_path)?;
    
    // Create unique temp file in same directory
    let temp_path = generate_temp_path(input_path)?;
    
    // Perform signing to temp file
    sign_zip_file(input_path, &temp_path, private_key)?;
    
    // Create backup of original
    fs::rename(input_path, &backup_path)
        .map_err(|e| format!("Failed to create backup: {}", e))?;
    
    // Move signed file to original location
    fs::rename(&temp_path, output_path)
        .map_err(|e| {
            // Attempt to restore backup on failure
            let _ = fs::rename(&backup_path, input_path);
            format!("Failed to finalize in-place signing: {}", e)
        })?;
    
    println!("Original file backed up to: {}", backup_path.display());
    println!("In-place signing completed at: {}", output_path.display());
    Ok(())
}

fn sign_zip_file(
    input_path: &Path,
    output_path: &Path,
    private_key: &PKey<openssl::pkey::Private>,
) -> Result<(), String> {
    let input_file = File::open(input_path)
        .map_err(|e| format!("Failed to open input file: {}", e))?;
    
    let mut archive = ZipArchive::new(input_file)
        .map_err(|e| format!("Invalid ZIP archive: {}", e))?;
    
    let output_file = File::create(output_path)
        .map_err(|e| format!("Failed to create output file: {}", e))?;
    
    let mut zip_writer = ZipWriter::new(output_file);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o755);

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
            .map_err(|e| format!("Error reading ZIP entry: {}", e))?;
        
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| format!("Error reading file contents: {}", e))?;

        // Handle BZIP2 decompression
        if file.compression() == CompressionMethod::Bzip2 {
            let mut decompressed = Vec::new();
            let mut decoder = bzip2::read::BzDecoder::new(&contents[..]);
            decoder.read_to_end(&mut decompressed)
                .map_err(|e| format!("BZIP2 decompression failed: {}", e))?;
            contents = decompressed;
        }

        // Sign file contents
        let signature = sign_data(private_key, &contents)?;

        // Write original file
        zip_writer.start_file(file.name(), options)
            .map_err(|e| format!("Failed to start file entry: {}", e))?;
        zip_writer.write_all(&contents)
            .map_err(|e| format!("Failed to write file contents: {}", e))?;

        // Write signature file
        let sig_filename = format!("{}.sig", file.name());
        zip_writer.start_file(&sig_filename, options)
            .map_err(|e| format!("Failed to start signature entry: {}", e))?;
        zip_writer.write_all(&signature)
            .map_err(|e| format!("Failed to write signature: {}", e))?;
    }

    zip_writer.finish()
        .map_err(|e| format!("Failed to finalize ZIP: {}", e))?;
    Ok(())
}

fn load_embedded_private_key() -> Result<PKey<openssl::pkey::Private>, String> {
    Rsa::private_key_from_pem(DEFAULT_PRIVATE_KEY.as_bytes())
        .map_err(|e| format!("Failed to parse embedded key: {}", e))
        .and_then(|rsa| PKey::from_rsa(rsa)
            .map_err(|e| format!("Failed to create key object: {}", e))
        )
}

fn load_private_key_from_file(path: &Path) -> Result<PKey<openssl::pkey::Private>, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open key file: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Failed to read key file: {}", e))?;
    
    Rsa::private_key_from_pem(contents.as_bytes())
        .map_err(|e| format!("Invalid PEM key file: {}", e))
        .and_then(|rsa| PKey::from_rsa(rsa)
            .map_err(|e| format!("Invalid RSA key: {}", e))
        )
}

fn sign_data(private_key: &PKey<openssl::pkey::Private>, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut signer = Signer::new(MessageDigest::sha256(), private_key)
        .map_err(|e| format!("Signer initialization failed: {}", e))?;
    
    signer.update(data)
        .map_err(|e| format!("Data update failed: {}", e))?;
    
    signer.sign_to_vec()
        .map_err(|e| format!("Signature generation failed: {}", e))
}

fn get_default_output_path(input_path: &Path) -> PathBuf {
    let stem = input_path.file_stem().unwrap().to_str().unwrap();
    let ext = input_path.extension().and_then(|e| e.to_str()).unwrap_or("zip");
    input_path.with_file_name(format!("{}_signed.{}", stem, ext))
}

fn generate_backup_path(input_path: &Path) -> Result<PathBuf, String> {
    let parent = input_path.parent().unwrap_or(Path::new("."));
    let stem = input_path.file_stem().unwrap().to_str().unwrap();
    let ext = input_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    // Generate timestamp (milliseconds since epoch)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_millis();

    // Create base backup name
    let backup_name = if ext.is_empty() {
        format!("{}_backup_{}", stem, timestamp)
    } else {
        format!("{}_backup_{}.{}", stem, timestamp, ext)
    };

    let mut backup_path = parent.join(backup_name);
    let mut counter = 0;

    // Ensure unique filename
    while backup_path.exists() {
        counter += 1;
        let unique_name = if ext.is_empty() {
            format!("{}_backup_{}_{}", stem, timestamp, counter)
        } else {
            format!("{}_backup_{}_{}.{}", stem, timestamp, counter, ext)
        };
        backup_path = parent.join(unique_name);
    }

    Ok(backup_path)
}

fn generate_temp_path(input_path: &Path) -> Result<PathBuf, String> {
    let parent = input_path.parent().unwrap_or(Path::new("."));
    let filename = input_path.file_name().unwrap().to_str().unwrap();
    
    // Generate random suffix
    let rand_suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    
    let mut temp_path = parent.join(format!("{}.tmp_{}", filename, rand_suffix));
    let mut counter = 0;

    // Ensure unique filename
    while temp_path.exists() {
        counter += 1;
        temp_path = parent.join(format!("{}.tmp_{}_{}", filename, rand_suffix, counter));
    }

    Ok(temp_path)
}