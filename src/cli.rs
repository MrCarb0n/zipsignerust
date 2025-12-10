/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2024 Tiash / @MrCarb0n and Earth Inc.
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
        .help_template("{about-with-newline}{usage-heading} {usage}\n\n{all-args}\n")
        .subcommand_required(true)
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
                        .help("Custom private key (PEM)"),
                )
                .arg(
                    Arg::new("public_key")
                        .short('p')
                        .long("public-key")
                        .help("Custom public key/cert (PEM)"),
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
        .get_matches();

    // Initialize UI state
    let verbose = matches.get_flag("verbose");
    let ui = Ui::new(verbose, false, true);

    ui.print_banner();

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
                "Verifying integrity of: `{}`",
                config.input_path.display()
            ));

            if ArtifactVerifier::verify(&config.input_path, &key_chain)? {
                ui.success("Signature is valid. The artifact is authentic.");
            }
        }
        config::Mode::Sign { inplace } => {
            ui.info("Loading cryptographic keys...");
            let key_chain =
                KeyChain::new(config.key_path.as_deref(), config.cert_path.as_deref(), ui)?;

            ui.print_mode_header("SIGNING MODE");
            ui.info(&format!("Source: `{}`", config.input_path.display()));
            ui.info(&format!("Target: `{}`", config.output_path.display()));

            if config.output_path.exists() && !inplace && !config.overwrite && !config.is_stdout {
                return Err(SignerError::Config(format!(
                    "Output file already exists: `{}`. Use --overwrite to proceed.",
                    config.output_path.display()
                )));
            }

            ui.info("Parsing archive and computing file digests...");
            let nested = signing::ArtifactProcessor::compute_digests_prepare_nested(
                &config.input_path,
                &key_chain,
                ui,
            )?;

            let working_input = if inplace {
                let backup = config.input_path.with_extension("bak");
                std::fs::rename(&config.input_path, &backup)?;
                ui.warn(&format!(
                    "Original file backed up to: `{}`",
                    backup.display()
                ));
                backup
            } else {
                config.input_path.clone()
            };

            ui.info("Generating signature and writing signed archive...");
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
                            "Custom (PEM)"
                        } else {
                            "Embedded (Test)"
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
                                ui.error("Original file has been restored from backup.");
                                return Err(e);
                            }
                            Err(restore_err) => {
                                ui.error(&format!(
                                    "CRITICAL: Failed to restore backup after error: {}",
                                    restore_err
                                ));
                                return Err(SignerError::Config(format!(
                                    "Signing failed AND backup restoration failed. Original error: {}. Restore error: {}. Backup location: {}",
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
