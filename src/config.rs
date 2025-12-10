/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::error::SignerError;
use clap::ArgMatches;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[derive(Debug, Clone)]
pub enum Mode {
    Sign { inplace: bool },
    Verify,
}

#[derive(Debug)]
pub struct Config {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub mode: Mode,
    pub key_path: Option<PathBuf>,
    pub cert_path: Option<PathBuf>,
    pub overwrite: bool,
    pub is_stdout: bool,
    pub _input_temp_file: Option<NamedTempFile>,
}

impl Config {
    pub fn from_matches(matches: &ArgMatches) -> Result<Self, SignerError> {
        match matches.subcommand() {
            Some(("sign", sub_matches)) => Self::parse_sign(sub_matches),
            Some(("verify", sub_matches)) => Self::parse_verify(sub_matches),
            _ => Err(SignerError::Config(
                "No subcommand provided. Use 'sign' or 'verify'.".into(),
            )),
        }
    }

    fn parse_sign(matches: &ArgMatches) -> Result<Self, SignerError> {
        let input_str = matches.get_one::<String>("input").unwrap();
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
                    "Input file not found: {}",
                    path.display()
                )));
            }
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
                        "Invalid filename (no stem or non-UTF8): {}",
                        input_path.display()
                    ))
                })?;
            input_path.with_file_name(format!("{}_signed.zip", stem))
        };

        let key_path = matches.get_one::<String>("private_key").map(PathBuf::from);
        let cert_path = matches.get_one::<String>("public_key").map(PathBuf::from);
        let overwrite = matches.get_flag("overwrite");

        Ok(Self {
            input_path,
            output_path,
            mode: Mode::Sign { inplace },
            key_path,
            cert_path,
            overwrite,
            is_stdout,
            _input_temp_file: input_temp_file,
        })
    }

    fn parse_verify(matches: &ArgMatches) -> Result<Self, SignerError> {
        let input_path = PathBuf::from(matches.get_one::<String>("input").unwrap());
        if !input_path.exists() {
            return Err(SignerError::Config(format!(
                "Input file not found: {}",
                input_path.display()
            )));
        }

        // For verification, output_path is irrelevant, but we keep it valid to satisfy the struct
        let output_path = input_path.clone();

        // Verification mainly needs the public key/cert
        let cert_path = matches
            .get_one::<String>("public_key")
            .map(Path::new)
            .map(|p| p.to_path_buf());
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
            _input_temp_file: None,
        })
    }
}
