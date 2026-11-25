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
    config::{self, Config},
    error::SignerError,
    keys::KeyChain,
    ui::{SummaryField, Ui},
    verification::ArtifactVerifier,
    *,
};
use clap::{Arg, ArgAction, Command};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

pub fn run() -> Result<(), SignerError> {
    // NOTE: `-h/--help` is handled by clap itself (`arg_required_else_help`
    // below prints help when no args are given). No hand-rolled help here.
    let mut cmd = Command::new(APP_NAME)
        .bin_name(binary_name())
        .version(APP_VERSION)
        .author(APP_AUTHOR)
        .about(APP_ABOUT)
        .disable_version_flag(true)
        .help_template("{about-with-newline}{usage-heading} {usage}\n\n{all-args}\n")
        .subcommand_required(false)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("sign")
                .about("Sign a ZIP archive")
                .arg_required_else_help(true)
                .arg(
                    Arg::new("input")
                        .required(true)
                        .help("Path to the input ZIP file (- for stdin)")
                        .index(1),
                )
                .arg(
                    Arg::new("output")
                        .help("Path to save the signed ZIP (- for stdout, optional)")
                        .index(2),
                )
                .arg(
                    Arg::new("private_key")
                        .short('k')
                        .long("private-key")
                        .help("Custom private key (PEM/PK8)"),
                )
                .arg(
                    Arg::new("public_key")
                        .short('p')
                        .long("public-key")
                        .help("Custom public key/cert (PEM/X509)"),
                )
                .arg(
                    Arg::new("overwrite")
                        .short('f')
                        .long("overwrite")
                        .action(ArgAction::SetTrue)
                        .help("Force overwrite if output exists"),
                )
                .arg(
                    Arg::new("inplace")
                        .short('i')
                        .long("inplace")
                        .action(ArgAction::SetTrue)
                        .help("Sign input file directly (keeps a timestamped .bak backup)"),
                ),
        )
        .subcommand(
            Command::new("verify")
                .about("Verify the signature of an archive")
                .arg_required_else_help(true)
                .arg(
                    Arg::new("input")
                        .required(true)
                        .help("Path to the archive to verify")
                        .index(1),
                )
                .arg(
                    Arg::new("public_key")
                        .short('p')
                        .long("public-key")
                        .help("Custom public key/cert (PEM) to verify against"),
                )
                .arg(
                    Arg::new("pin")
                        .short('P')
                        .long("pin")
                        .help("Expected signer certificate SHA-256 fingerprint (AA:BB:… or hex)"),
                ),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .help("Set verbosity level (-v for verbose, -vv for more verbose, -vvv for debug)"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::SetTrue)
                .help("Suppress all output except errors"),
        )
        .arg(
            Arg::new("version_custom")
                .short('V')
                .long("version")
                .action(ArgAction::SetTrue)
                .help("Print version information"),
        );
    let matches = cmd.clone().get_matches();

    if matches.get_flag("version_custom") {
        let mut ui = Ui::new(false, false, false, false, true);
        ui.force_color_on_windows();
        ui.print_version_info();
        return Ok(());
    }

    if matches.subcommand().is_none() {
        cmd.print_help().ok();
        println!();
        return Ok(());
    }

    let verbosity_level = matches.get_count("verbose");
    let quiet = matches.get_flag("quiet");
    let mut ui = Ui::from_verbosity_level(verbosity_level, quiet, true);

    // Enable colors if supported on the platform
    ui.force_color_on_windows();

    ui.print_banner();

    run_logic(&matches, &ui)
}

fn run_logic(matches: &clap::ArgMatches, ui: &Ui) -> Result<(), SignerError> {
    let config = Config::from_matches(matches, ui)?;
    match config.mode {
        config::Mode::Verify => run_verify(&config, ui),
        config::Mode::Sign { inplace } => run_sign(&config, inplace, ui),
    }
}

fn run_verify(config: &Config, ui: &Ui) -> Result<(), SignerError> {
    let key_chain = if config.cert_path.is_some() || config.pin.is_none() {
        Some(KeyChain::for_verification(config.cert_path.as_deref(), ui)?)
    } else {
        None
    };

    ui.print_mode_header("VERIFICATION MODE");
    ui.info(&format!(
        "Verifying integrity: {}",
        config.input_path.display()
    ));

    ui.info(&format!(
        "Starting verification process for: {}",
        config.input_path.display()
    ));
    if ArtifactVerifier::verify_trusted(
        &config.input_path,
        key_chain.as_ref(),
        ui,
        config.pin.as_deref(),
    )? {
        ui.success("Signature valid for the expected signer.");
        ui.info("Verification completed successfully");
        if ui.verbose {
            eprintln!();
        }
    } else {
        return Err(SignerError::Validation("Signature is invalid".into()));
    }
    Ok(())
}

fn run_sign(config: &Config, inplace: bool, ui: &Ui) -> Result<(), SignerError> {
    ui.info("Loading keys...");
    let key_chain = KeyChain::new(config.key_path.as_deref(), config.cert_path.as_deref(), ui)?;

    if let Some(ref key_path) = config.key_path {
        ui.debug(&format!("Using custom private key: {}", key_path.display()));
    } else {
        ui.debug("Using default development private key");
    }

    if let Some(ref cert_path) = config.cert_path {
        ui.debug(&format!(
            "Using custom certificate: {}",
            cert_path.display()
        ));
    } else {
        ui.debug("Using default development certificate");
    }

    ui.print_mode_header("SIGNING MODE");
    ui.debug(&format!("In-place mode: {}", inplace));

    if config.input_temp_file.is_some() {
        ui.info("Source: <stdin pipe>");
        ui.debug(&format!("Temporary input file: {:?}", config.input_path));
    } else {
        ui.info(&format!("Source: {}", config.input_path.display()));
    }

    if config.is_stdout {
        ui.info("Target: <stdout pipe>");
    } else {
        ui.info(&format!("Target: {}", config.output_path.display()));
    }

    use processor::ArtifactProcessor;
    if !inplace && !config.is_stdout {
        ArtifactProcessor::check_distinct_paths(&config.input_path, &config.output_path)?;
    }

    ui.info("Computing digests...");
    ui.info(&format!(
        "Processing input archive: {}",
        config.input_path.display()
    ));
    let nested = processor::ArtifactProcessor::compute_digests_prepare_nested(
        &config.input_path,
        &key_chain,
        ui,
    )?;
    ui.debug(&format!(
        "Successfully computed digests for {} files",
        nested.digests.len()
    ));
    ui.debug(&format!(
        "Found {} nested archives for processing",
        nested.nested_files.len()
    ));

    ui.info("Signing artifact...");
    let temp_dir = std::env::temp_dir();
    let output = if inplace {
        fs::canonicalize(&config.input_path)?
    } else {
        config.output_path.clone()
    };
    let directory = if config.is_stdout {
        &temp_dir
    } else {
        ArtifactProcessor::output_dir(&output)
    };
    let mut staged = ArtifactProcessor::stage_signed_zip(
        &config.input_path,
        directory,
        &key_chain,
        &nested.digests,
        &nested.nested_files,
        ui,
    )?;
    if config.is_stdout {
        io::copy(staged.as_file_mut(), &mut io::stdout())?;
        return Ok(());
    }
    let backup = if inplace {
        let backup = create_backup(&output)?;
        ui.warn(&format!("Backup created: {}", backup.display()));
        staged
            .as_file()
            .set_permissions(fs::metadata(&output)?.permissions())?;
        Some(backup)
    } else {
        None
    };
    if inplace || config.overwrite {
        staged.persist(&output).map_err(|e| e.error)?;
    } else {
        staged.persist_noclobber(&output).map_err(|e| {
            if e.error.kind() == io::ErrorKind::AlreadyExists {
                SignerError::Config(format!(
                    "Output exists: {}. Use --overwrite.",
                    output.display()
                ))
            } else {
                e.error.into()
            }
        })?;
    }
    finish_sign(config, backup.as_deref(), ui);
    Ok(())
}

fn finish_sign(config: &Config, backup: Option<&Path>, ui: &Ui) {
    if let Some(working_input) = backup {
        ui.success("In-place signing complete.");
        ui.info(&format!("Backup kept: {}", working_input.display()));
        if ui.verbose {
            eprintln!();
        }
        let key_type = key_type_label(config);
        ui.print_summary(
            "Signing Report",
            &[
                SummaryField::new("Status", "Success"),
                SummaryField::new("Mode", "In-Place"),
                SummaryField::new("File", config.input_path.display().to_string()),
                SummaryField::new("Backup", working_input.display().to_string()),
                SummaryField::new("Key Used", key_type.to_string()),
            ],
        );
    } else {
        ui.success("Archive successfully signed.");
        if ui.verbose {
            eprintln!();
        }
        let key_type = key_type_label(config);
        ui.print_summary(
            "Signing Report",
            &[
                SummaryField::new("Status", "Success"),
                SummaryField::new("Mode", "Standard"),
                SummaryField::new("Input", config.input_path.display().to_string()),
                SummaryField::new("Output", config.output_path.display().to_string()),
                SummaryField::new("Key Used", key_type.to_string()),
            ],
        );
    }
}

fn key_type_label(config: &Config) -> &'static str {
    if config.key_path.is_some() {
        "Custom (PEM/PK8)"
    } else {
        "ZipSignerust Dev"
    }
}

fn binary_name() -> String {
    std::env::args()
        .next()
        .unwrap_or_else(|| APP_BIN_NAME.to_string())
}

/// Timestamped backup path: `input.zip` -> `input.zip.260114092033.bak`
/// (`yymmddhhmmss`, UTC), reserved uniquely so an existing backup is never overwritten.
fn create_backup(path: &Path) -> io::Result<PathBuf> {
    let now = x509_parser::prelude::ASN1Time::now().to_datetime();
    let stamp = format!(
        ".{:02}{:02}{:02}{:02}{:02}{:02}",
        now.year() % 100,
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let mut original = fs::File::open(path)?;
    let mut staged = NamedTempFile::new_in(processor::ArtifactProcessor::output_dir(path))?;
    io::copy(&mut original, &mut staged)?;
    staged
        .as_file()
        .set_permissions(original.metadata()?.permissions())?;
    staged.as_file().sync_all()?;
    for i in 0..=u32::MAX {
        let mut name = path.as_os_str().to_owned();
        name.push(&stamp);
        if i != 0 {
            name.push(format!(".{i}"));
        }
        name.push(".bak");
        let backup = PathBuf::from(name);
        match staged.persist_noclobber(&backup) {
            Ok(_) => return Ok(backup),
            Err(err) if err.error.kind() == io::ErrorKind::AlreadyExists => staged = err.file,
            Err(err) => return Err(err.error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free backup name",
    ))
}
