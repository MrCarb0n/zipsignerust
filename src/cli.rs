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
use std::io;
use tempfile::NamedTempFile;

pub fn run() -> Result<(), SignerError> {
    // NOTE: `-h/--help` is handled by clap itself (`arg_required_else_help`
    // below prints help when no args are given). No hand-rolled help here.
    let matches = Command::new(APP_NAME)
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
                        .help("Sign input file directly (creates backup)"),
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
        )
        .get_matches();

    if matches.get_flag("version_custom") {
        let mut ui = Ui::new(false, false, false, false, true);
        ui.force_color_on_windows();
        ui.print_version_info();
        return Ok(());
    }

    let verbosity_level = matches.get_count("verbose") as u8;
    let quiet = matches.get_flag("quiet");
    let mut ui = Ui::from_verbosity_level(verbosity_level, quiet, true);

    // Enable colors if supported on the platform
    ui.force_color_on_windows();

    ui.print_banner();

    if matches.subcommand().is_none() {
        return Err(SignerError::Config("No command provided".into()));
    }

    run_logic(&matches, &ui)
}

fn run_logic(matches: &clap::ArgMatches, ui: &Ui) -> Result<(), SignerError> {
    let mut config = Config::from_matches(matches, ui)?;

    let output_temp_file = prepare_output_tempfile(&mut config, ui)?;

    let result = match config.mode.clone() {
        config::Mode::Verify => run_verify(&config, ui),
        config::Mode::Sign { inplace } => run_sign(&config, &output_temp_file, inplace, ui),
    };

    // NamedTempFile cleans up on drop; keep it alive through the function.
    drop(output_temp_file);

    if result.is_ok() {
        ui.print_temp_files();
    }
    result
}

fn prepare_output_tempfile(
    config: &mut Config,
    ui: &Ui,
) -> Result<Option<NamedTempFile>, SignerError> {
    if !config.is_stdout {
        return Ok(None);
    }
    let temp_file = NamedTempFile::new().map_err(|e| {
        SignerError::Config(format!("Failed to create temp file for stdout: {}", e))
    })?;
    ui.debug(&format!(
        "Created temporary output file: {:?}",
        temp_file.path()
    ));
    if config.verbose {
        ui.info(&format!(
            "Using temporary output file: {:?}",
            temp_file.path()
        ));
    }
    config.output_path = temp_file.path().to_path_buf();
    ui.record_temp_file(temp_file.path());
    Ok(Some(temp_file))
}

fn run_verify(config: &Config, ui: &Ui) -> Result<(), SignerError> {
    let key_chain = KeyChain::new(None, config.cert_path.as_deref(), ui)?;

    ui.print_mode_header("VERIFICATION MODE");
    ui.info(&format!(
        "Verifying integrity: {}",
        config.input_path.display()
    ));

    if let Some(ref cert_path) = config.cert_path {
        ui.info(&format!(
            "Using custom certificate for verification: {}",
            cert_path.display()
        ));
    } else {
        ui.info("Using default development certificate for verification");
    }

    ui.info(&format!(
        "Starting verification process for: {}",
        config.input_path.display()
    ));
    if ArtifactVerifier::verify(&config.input_path, &key_chain, ui)? {
        ui.success("Signature valid. Artifact authentic.");
        ui.info("Verification completed successfully");
        if ui.verbose {
            eprintln!();
        }
    } else {
        ui.info("Verification completed - signature is invalid");
    }
    Ok(())
}

fn run_sign(
    config: &Config,
    output_temp_file: &Option<NamedTempFile>,
    inplace: bool,
    ui: &Ui,
) -> Result<(), SignerError> {
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
        if let Some(ref temp_file) = output_temp_file {
            ui.debug(&format!("Temporary output file: {:?}", temp_file.path()));
        }
    } else {
        ui.info(&format!("Target: {}", config.output_path.display()));
    }

    if config.output_path.exists() && !inplace && !config.overwrite && !config.is_stdout {
        return Err(SignerError::Config(format!(
            "Output exists: {}. Use --overwrite.",
            config.output_path.display()
        )));
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

    let working_input = if inplace {
        let backup = append_backup_suffix(&config.input_path);
        ui.debug(&format!(
            "Creating backup: {} -> {}",
            config.input_path.display(),
            backup.display()
        ));
        rename_or_copy(&config.input_path, &backup)?;
        ui.warn(&format!("Backup created: {}", backup.display()));
        backup
    } else {
        config.input_path.clone()
    };

    ui.info("Signing artifact...");
    ui.debug(&format!(
        "Writing signed output to: {}",
        config.output_path.display()
    ));
    ui.debug(&format!(
        "Using {} digests for signing",
        nested.digests.len()
    ));
    ui.debug(&format!(
        "Processing {} nested files",
        nested.nested_files.len()
    ));

    let write_result = processor::ArtifactProcessor::write_signed_zip_with_sources(
        &working_input,
        &config.output_path,
        &key_chain,
        &nested.digests,
        &nested.nested_files,
        ui,
    );

    match write_result {
        Ok(_) => {
            ui.debug(&format!(
                "Successfully wrote signed archive to: {}",
                config.output_path.display()
            ));
            finish_sign(config, &working_input, inplace, ui)?;
            Ok(())
        }
        Err(e) => {
            if inplace {
                return Err(restore_backup(working_input, &config.input_path, e, ui));
            }
            Err(e)
        }
    }
}

fn finish_sign(
    config: &Config,
    working_input: &std::path::Path,
    inplace: bool,
    ui: &Ui,
) -> Result<(), SignerError> {
    if inplace {
        ui.info(&format!(
            "Removing temporary working file: {:?}",
            working_input
        ));
        std::fs::remove_file(working_input)?;
        ui.success("In-place signing complete.");
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
                SummaryField::new("Key Used", key_type.to_string()),
            ],
        );
    } else if config.is_stdout {
        ui.debug("Copying final output to stdout...");
        let mut file = std::fs::File::open(&config.output_path)?;
        let mut stdout = io::stdout();
        io::copy(&mut file, &mut stdout)?;
        ui.debug("Successfully wrote to stdout");
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
    Ok(())
}

fn restore_backup(
    working_input: std::path::PathBuf,
    original: &std::path::Path,
    signing_err: SignerError,
    ui: &Ui,
) -> SignerError {
    match rename_or_copy(&working_input, original) {
        Ok(_) => {
            ui.error("Original file restored from backup.");
            signing_err
        }
        Err(restore_err) => {
            ui.error(&format!("CRITICAL: Backup restore failed: {}", restore_err));
            SignerError::Config(format!(
                "Signing failed AND restore failed. Error: {}. Restore: {}. Backup: {}",
                signing_err,
                restore_err,
                working_input.display()
            ))
        }
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

/// Append a `.bak` suffix to a path, preserving the original extension.
///
/// Industry-standard convention (used by editors, build tools, and most CLI
/// tools) is to append the suffix rather than replace the extension. This
/// keeps the original filename recognizable and avoids losing multi-part
/// extensions like `.tar.gz` -> `.tar.bak`.
fn append_backup_suffix(path: &std::path::Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    std::path::PathBuf::from(s)
}

/// Rename `src` to `dst`, falling back to copy+remove if the rename crosses
/// a filesystem boundary (where `rename` returns `EXDEV` on Unix or
/// `ERROR_NOT_SAME_DEVICE` on Windows).
///
/// This matters for `--inplace` because the working `.bak` file may live on
/// a different filesystem than the original input (e.g. a bind-mounted
/// `input.apk` vs a `.bak` in a normal directory).
fn rename_or_copy(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) => {
            if is_cross_device(&e) {
                std::fs::copy(src, dst)?;
                std::fs::remove_file(src)?;
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

fn is_cross_device(e: &std::io::Error) -> bool {
    // ponytail: std maps EXDEV/ERROR_NOT_SAME_DEVICE to CrossesDevices; raw 18/17 kept for old toolchains
    e.kind() == std::io::ErrorKind::CrossesDevices
        || matches!(e.raw_os_error(), Some(18) | Some(17))
}
