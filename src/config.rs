/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

//! Configuration parsing and validation for the ZipSigner CLI.
//! Handles command line arguments and sets up application configuration.

use crate::error::SignerError;
use clap::ArgMatches;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Execution mode for the application.
#[derive(Debug, Clone)]
pub enum Mode {
    /// Sign an archive with optional in-place modification
    Sign { inplace: bool },
    /// Verify an archive's signature
    Verify,
}

/// Application configuration parsed from command-line arguments.
#[derive(Debug)]
pub struct Config {
    /// Path to the input file to process
    pub input_path: PathBuf,
    /// Path where the output should be written
    pub output_path: PathBuf,
    /// Execution mode (sign/verify)
    pub mode: Mode,
    /// Path to custom private key file (if provided)
    pub key_path: Option<PathBuf>,
    /// Path to custom certificate/public key file (if provided)
    pub cert_path: Option<PathBuf>,
    /// Whether to overwrite existing output files
    pub overwrite: bool,
    /// Whether output should be written to stdout
    pub is_stdout: bool,
    /// Whether to suppress non-error output
    pub quiet: bool,
    /// Temporary file for stdin input handling
    pub _input_temp_file: Option<NamedTempFile>,
}

impl Config {
    /// Parse configuration from command-line argument matches.
    ///
    /// # Arguments
    /// * `matches` - The clap argument matches structure
    ///
    /// # Returns
    /// Configuration object or an error
    pub fn from_matches(matches: &ArgMatches) -> Result<Self, SignerError> {
        let quiet = matches.get_flag("quiet");

        match matches.subcommand() {
            Some(("sign", sub_matches)) => Self::parse_sign(sub_matches, quiet),
            Some(("verify", sub_matches)) => Self::parse_verify(sub_matches, quiet),
            _ => Err(SignerError::Config(
                "No subcommand provided. Use 'sign' or 'verify'.".into(),
            )),
        }
    }

    /// Parse signing mode configuration.
    ///
    /// # Arguments
    /// * `matches` - The clap subcommand matches for signing
    /// * `quiet` - Whether to suppress non-error output
    ///
    /// # Returns
    /// Configuration object for signing mode or an error
    fn parse_sign(matches: &ArgMatches, quiet: bool) -> Result<Self, SignerError> {
        let input_str = matches
            .get_one::<String>("input")
            .ok_or_else(|| SignerError::Config("No input file specified".into()))?;

        let (input_path, input_temp_file) = if input_str == "-" {
            let mut temp = NamedTempFile::new().map_err(|e| {
                SignerError::Config(format!("Failed to create temp file for stdin: {}", e))
            })?;
            let mut stdin = io::stdin();
            io::copy(&mut stdin, &mut temp)
                .map_err(|e| SignerError::Config(format!("Failed to read stdin: {}", e)))?;
            (temp.path().to_path_buf(), Some(temp))
        } else {
            let path = PathBuf::from(input_str);
            if !path.exists() {
                return Err(SignerError::Config(format!(
                    "Input file does not exist: {}",
                    path.display()
                )));
            }
            // Validate that input is a readable file
            std::fs::metadata(&path).map_err(|e| {
                SignerError::Config(format!(
                    "Cannot access input file {}: {}",
                    path.display(),
                    e
                ))
            })?;
            (path, None)
        };

        let inplace = matches.get_flag("inplace");
        if inplace && input_temp_file.is_some() {
            return Err(SignerError::Config(
                "Cannot use --inplace with stdin input.".into(),
            ));
        }

        let mut is_stdout = false;
        let output_path = if inplace {
            input_path.clone()
        } else if let Some(out) = matches.get_one::<String>("output") {
            if out == "-" {
                is_stdout = true;
                PathBuf::from("stdout")
            } else {
                PathBuf::from(out)
            }
        } else if input_temp_file.is_some() {
            is_stdout = true;
            PathBuf::from("stdout")
        } else {
            let stem = input_path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| {
                    SignerError::Config(format!(
                        "Invalid input filename (no stem or non-UTF8): {}",
                        input_path.display()
                    ))
                })?;
            input_path.with_file_name(format!("{}_signed.zip", stem))
        };

        // Validate key paths exist if provided
        let key_path = if let Some(key_str) = matches.get_one::<String>("private_key") {
            let key_path = PathBuf::from(key_str);
            if !key_path.exists() {
                return Err(SignerError::Config(format!(
                    "Private key file does not exist: {}",
                    key_path.display()
                )));
            }
            Some(key_path)
        } else {
            None
        };

        let cert_path = if let Some(cert_str) = matches.get_one::<String>("public_key") {
            let cert_path = PathBuf::from(cert_str);
            if !cert_path.exists() {
                return Err(SignerError::Config(format!(
                    "Certificate file does not exist: {}",
                    cert_path.display()
                )));
            }
            Some(cert_path)
        } else {
            None
        };

        let overwrite = matches.get_flag("overwrite");

        Ok(Self {
            input_path,
            output_path,
            mode: Mode::Sign { inplace },
            key_path,
            cert_path,
            overwrite,
            is_stdout,
            quiet,
            _input_temp_file: input_temp_file,
        })
    }

    /// Parse verification mode configuration.
    ///
    /// # Arguments
    /// * `matches` - The clap subcommand matches for verification
    /// * `quiet` - Whether to suppress non-error output
    ///
    /// # Returns
    /// Configuration object for verification mode or an error
    fn parse_verify(matches: &ArgMatches, quiet: bool) -> Result<Self, SignerError> {
        let input_path = PathBuf::from(
            matches
                .get_one::<String>("input")
                .ok_or_else(|| SignerError::Config("No input file specified for verification".into()))?
        );

        if !input_path.exists() {
            return Err(SignerError::Config(format!(
                "Input file does not exist: {}",
                input_path.display()
            )));
        }

        // Validate that input is a readable file
        std::fs::metadata(&input_path).map_err(|e| {
            SignerError::Config(format!(
                "Cannot access input file {}: {}",
                input_path.display(),
                e
            ))
        })?;

        // For verification, output_path is irrelevant, but we keep it valid to satisfy the struct
        let output_path = input_path.clone();

        // Verification mainly needs the public key/cert
        let cert_path = if let Some(cert_str) = matches.get_one::<String>("public_key") {
            let cert_path = Path::new(cert_str);
            if !cert_path.exists() {
                return Err(SignerError::Config(format!(
                    "Certificate file does not exist: {}",
                    cert_path.display()
                )));
            }
            Some(cert_path.to_path_buf())
        } else {
            None
        };

        // Private key is irrelevant for verify, but we parse it if passed (unlikely in this mode)
        let key_path = None;

        Ok(Self {
            input_path,
            output_path,
            mode: Mode::Verify,
            key_path,
            cert_path,
            overwrite: false,
            is_stdout: false,
            quiet,
            _input_temp_file: None,
        })
    }
}
