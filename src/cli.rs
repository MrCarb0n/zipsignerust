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
    ui::Ui,
    verification::ArtifactVerifier,
    *,
};
use clap::{Arg, ArgAction, Command};
use colored::Colorize;
use std::io;
use tempfile::NamedTempFile;

pub fn run() -> Result<(), SignerError> {
    let binary_name = std::env::args()
        .next()
        .and_then(|p| {
            std::path::Path::new(&p)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| APP_BIN_NAME.to_string());

    // Check if help is requested before building the full command
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || (args.len() >= 2 && (args[1] == "-h" || args[1] == "--help")) {
        print_formatted_help()?;
        return Ok(());
    }

    // Check if a subcommand help is requested
    if args.len() >= 3 && (args[2] == "-h" || args[2] == "--help") {
        match args[1].as_str() {
            "sign" => {
                print_sign_help()?;
                return Ok(());
            }
            "verify" => {
                print_verify_help()?;
                return Ok(());
            }
            _ => {}
        }
    }

    let matches = Command::new(APP_NAME)
        .bin_name(binary_name)
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
        ui.enable_colors_if_supported();
        ui.print_version_info();
        return Ok(());
    }

    let verbosity_level = matches.get_count("verbose") as u8;
    let quiet = matches.get_flag("quiet");
    let mut ui = Ui::from_verbosity_level(verbosity_level, quiet, true);

    // Enable colors if supported on the platform
    ui.enable_colors_if_supported();

    ui.print_banner();

    if matches.subcommand().is_none() {
        return Err(SignerError::Config("No command provided".into()));
    }

    run_logic(&matches, &ui)
}

fn run_logic(matches: &clap::ArgMatches, ui: &Ui) -> Result<(), SignerError> {
    let mut config = Config::from_matches(matches, ui)?;

    let output_temp_file = if config.is_stdout {
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
        Some(temp_file)
    } else {
        None
    };

    if let Some(ref temp) = output_temp_file {
        config.output_path = temp.path().to_path_buf();
        ui.record_temp_file(temp.path());
    }

    match config.mode {
        config::Mode::Verify => {
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
                // Add a small vertical space after verification result for better visual separation
                if ui.verbose {
                    eprintln!();
                }
            } else {
                ui.info("Verification completed - signature is invalid");
            }
        }
        config::Mode::Sign { inplace } => {
            ui.info("Loading keys...");
            let key_chain =
                KeyChain::new(config.key_path.as_deref(), config.cert_path.as_deref(), ui)?;

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

            if config._input_temp_file.is_some() {
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
                let backup = config.input_path.with_extension("bak");
                ui.debug(&format!(
                    "Creating backup: {} -> {}",
                    config.input_path.display(),
                    backup.display()
                ));
                std::fs::rename(&config.input_path, &backup)?;
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

            match processor::ArtifactProcessor::write_signed_zip_with_sources(
                &working_input,
                &config.output_path,
                &key_chain,
                &nested.digests,
                &nested.nested_files,
                ui,
            ) {
                Ok(_) => {
                    ui.debug(&format!(
                        "Successfully wrote signed archive to: {}",
                        config.output_path.display()
                    ));

                    if inplace {
                        ui.info(&format!(
                            "Removing temporary working file: {:?}",
                            working_input
                        ));
                        std::fs::remove_file(&working_input)?;
                        ui.success("In-place signing complete.");

                        // Add visual separation before the signing report
                        if ui.verbose {
                            eprintln!();
                        }

                        let key_type = if config.key_path.is_some() {
                            "Custom (PEM/PK8)"
                        } else {
                            "ZipSignerust Dev"
                        };

                        ui.print_summary(
                            "Signing Report",
                            &[
                                ("Status", "Success".to_string()),
                                ("Mode", "In-Place".to_string()),
                                ("File", config.input_path.display().to_string()),
                                ("Key Used", key_type.to_string()),
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

                        let key_type = if config.key_path.is_some() {
                            "Custom (PEM/PK8)"
                        } else {
                            "ZipSignerust Dev"
                        };

                        // Add visual separation before the signing report
                        if ui.verbose {
                            eprintln!();
                        }

                        ui.print_summary(
                            "Signing Report",
                            &[
                                ("Status", "Success".to_string()),
                                ("Mode", "Standard".to_string()),
                                ("Input", config.input_path.display().to_string()),
                                ("Output", config.output_path.display().to_string()),
                                ("Key Used", key_type.to_string()),
                            ],
                        );
                    }
                }
                Err(e) => {
                    if inplace {
                        match std::fs::rename(&working_input, &config.input_path) {
                            Ok(_) => {
                                ui.error("Original file restored from backup.");
                                return Err(e);
                            }
                            Err(restore_err) => {
                                ui.error(&format!(
                                    "CRITICAL: Backup restore failed: {}",
                                    restore_err
                                ));
                                return Err(SignerError::Config(format!(
                                    "Signing failed AND restore failed. Error: {}. Restore: {}. Backup: {}",
                                    e, restore_err, working_input.display()
                                )));
                            }
                        }
                    }
                    return Err(e);
                }
            }
        }
    }

    // Print temporary files that were created if in debug mode
    ui.print_temp_files();

    Ok(())
}

/// Print help with UI formatting for consistent indentation
fn print_formatted_help() -> Result<(), SignerError> {
    let mut ui = Ui::default();
    ui.enable_colors_if_supported();

    // Print the application description with UI formatting
    ui.info("High-performance, memory-safe cryptographic signing and verification for Android ZIP archives.");

    // Print usage
    eprintln!();
    if ui.supports_color() {
        eprintln!("{}", format!("{}", "Usage:".bold().blue()).blue());
        let usage = format!("  {} [OPTIONS] [COMMAND]", std::env::args().next().unwrap_or_else(|| "zipsignerust".to_string()).as_str().cyan());
        eprintln!("{}", usage);
    } else {
        eprintln!("{}", "Usage:".blue());
        let usage = format!("  {} [OPTIONS] [COMMAND]", std::env::args().next().unwrap_or_else(|| "zipsignerust".to_string()));
        eprintln!("{}", usage);
    }

    eprintln!();

    // Print commands section using standardized UI
    ui.print_help_section("Commands", &[
        ("sign", "Sign a ZIP archive"),
        ("verify", "Verify the signature of an archive"),
        ("help", "Print this message or the help of the given subcommand(s)"),
    ]);

    // Print options section using standardized UI
    ui.print_help_section("Options", &[
        ("-v, --verbose", "Set verbosity level (-v for verbose, -vv for more verbose, -vvv for debug)"),
        ("-q, --quiet", "Suppress all output except errors"),
        ("-V, --version", "Print version information"),
        ("-h, --help", "Print help"),
    ]);

    Ok(())
}

/// Print sign subcommand help with UI formatting for consistency
fn print_sign_help() -> Result<(), SignerError> {
    let mut ui = Ui::default();
    ui.enable_colors_if_supported();

    // Print usage for sign command
    eprintln!();
    if ui.supports_color() {
        eprintln!("{}", format!("{}", "Usage:".bold().blue()).blue());
        let usage = format!("  {} sign [OPTIONS] <INPUT> [OUTPUT]", std::env::args().next().unwrap_or_else(|| "zipsignerust".to_string()).as_str().cyan());
        eprintln!("{}", usage);
    } else {
        eprintln!("{}", "Usage:".blue());
        let usage = format!("  {} sign [OPTIONS] <INPUT> [OUTPUT]", std::env::args().next().unwrap_or_else(|| "zipsignerust".to_string()));
        eprintln!("{}", usage);
    }

    eprintln!();

    // Print description
    ui.info("Sign a ZIP archive");

    eprintln!();

    // Print options section using standardized UI
    ui.print_help_section("Arguments", &[
        ("<INPUT>", "Path to the input ZIP file (- for stdin)"),
        ("[OUTPUT]", "Path to save the signed ZIP (- for stdout, optional)"),
    ]);

    eprintln!();

    ui.print_help_section("Options", &[
        ("-k KEY", "Custom private key (PEM/PK8)"),
        ("-p CERT", "Custom public key/cert (PEM/X509)"),
        ("-f", "Force overwrite if output exists"),
        ("-i", "Sign input file directly (creates backup)"),
        ("-v", "Set verbosity level (-v for verbose, -vv for more verbose, -vvv for debug)"),
        ("-q", "Suppress all output except errors"),
        ("-h", "Print help"),
    ]);

    Ok(())
}

/// Print verify subcommand help with UI formatting for consistency
fn print_verify_help() -> Result<(), SignerError> {
    let mut ui = Ui::default();
    ui.enable_colors_if_supported();

    // Print usage for verify command
    eprintln!();
    if ui.supports_color() {
        eprintln!("{}", format!("{}", "Usage:".bold().blue()).blue());
        let usage = format!("  {} verify [OPTIONS] <INPUT>", std::env::args().next().unwrap_or_else(|| "zipsignerust".to_string()).as_str().cyan());
        eprintln!("{}", usage);
    } else {
        eprintln!("{}", "Usage:".blue());
        let usage = format!("  {} verify [OPTIONS] <INPUT>", std::env::args().next().unwrap_or_else(|| "zipsignerust".to_string()));
        eprintln!("{}", usage);
    }

    eprintln!();

    // Print description
    ui.info("Verify the signature of an archive");

    eprintln!();

    // Print options section using standardized UI
    ui.print_help_section("Arguments", &[
        ("<INPUT>", "Path to the archive to verify"),
    ]);

    eprintln!();

    ui.print_help_section("Options", &[
        ("-p CERT", "Custom public key/cert (PEM) to verify against"),
        ("-v", "Set verbosity level (-v for verbose, -vv for more verbose, -vvv for debug)"),
        ("-q", "Suppress all output except errors"),
        ("-h", "Print help"),
    ]);

    Ok(())
}

