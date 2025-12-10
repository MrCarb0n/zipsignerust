/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::{
    config::{self, Config},
    error::SignerError,
    signing::{self, KeyChain},
    ui::Ui,
    verification::ArtifactVerifier,
    *,
};
use clap::{Arg, ArgAction, Command};
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
                .about("Sign a ZIP/APK/JAR archive")
                .arg_required_else_help(true)
                .arg(
                    Arg::new("input")
                        .required(true)
                        .help("Path to the input ZIP file")
                        .index(1),
                )
                .arg(
                    Arg::new("output")
                        .help("Path to save the signed ZIP (optional)")
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
                .action(ArgAction::SetTrue)
                .help("Enable verbose logging"),
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
        let ui = Ui::new(false, false, true);
        ui.print_version_info();
        return Ok(());
    }

    let verbose = matches.get_flag("verbose");
    let quiet = matches.get_flag("quiet");
    let ui = Ui::new(verbose, quiet, true);

    ui.print_banner();

    if matches.subcommand().is_none() {
        return Err(SignerError::Config("No command provided".into()));
    }

    run_logic(&matches, &ui)
}

fn run_logic(matches: &clap::ArgMatches, ui: &Ui) -> Result<(), SignerError> {
    let mut config = Config::from_matches(matches)?;

    let output_temp_file = if config.is_stdout {
        Some(NamedTempFile::new().map_err(|e| {
            SignerError::Config(format!("Failed to create temp file for stdout: {}", e))
        })?)
    } else {
        None
    };

    if let Some(ref temp) = output_temp_file {
        config.output_path = temp.path().to_path_buf();
    }

    match config.mode {
        config::Mode::Verify => {
            let key_chain = KeyChain::new(None, config.cert_path.as_deref(), ui)?;

            ui.print_mode_header("VERIFICATION MODE");
            ui.info(&format!(
                "Verifying integrity: {}",
                config.input_path.display()
            ));

            if ArtifactVerifier::verify(&config.input_path, &key_chain)? {
                ui.success("Signature valid. Artifact authentic.");
            }
        }
        config::Mode::Sign { inplace } => {
            ui.info("Loading keys...");
            let key_chain =
                KeyChain::new(config.key_path.as_deref(), config.cert_path.as_deref(), ui)?;

            ui.print_mode_header("SIGNING MODE");

            if config._input_temp_file.is_some() {
                ui.info("Source: <stdin pipe>");
            } else {
                ui.info(&format!("Source: {}", config.input_path.display()));
            }

            if config.is_stdout {
                ui.info("Target: <stdout pipe>");
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
            let nested = signing::ArtifactProcessor::compute_digests_prepare_nested(
                &config.input_path,
                &key_chain,
                ui,
            )?;

            let working_input = if inplace {
                let backup = config.input_path.with_extension("bak");
                std::fs::rename(&config.input_path, &backup)?;
                ui.warn(&format!("Backup created: {}", backup.display()));
                backup
            } else {
                config.input_path.clone()
            };

            ui.info("Signing artifact...");
            match signing::ArtifactProcessor::write_signed_zip_with_sources(
                &working_input,
                &config.output_path,
                &key_chain,
                &nested.digests,
                &nested.nested_sources,
                ui,
            ) {
                Ok(_) => {
                    if inplace {
                        std::fs::remove_file(&working_input)?;
                        ui.success("In-place signing complete.");

                        ui.print_summary(
                            "Signing Report",
                            &[
                                ("Status", "Success".to_string()),
                                ("Mode", "In-Place".to_string()),
                                ("File", config.input_path.display().to_string()),
                            ],
                        );
                    } else if config.is_stdout {
                        let mut file = std::fs::File::open(&config.output_path)?;
                        let mut stdout = io::stdout();
                        io::copy(&mut file, &mut stdout)?;
                    } else {
                        ui.success("Archive successfully signed.");

                        let key_type = if config.key_path.is_some() {
                            "Custom (PEM/PK8)"
                        } else {
                            "ZipSignerust Dev"
                        };

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
    Ok(())
}
