/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2024 Tiash / @MrCarb0n and Earth Inc.
 * Licensed under the MIT License.
 * -----------------------
 * Main entry point for the application.
 */

use zipsignerust::cli;
use zipsignerust::ui;

fn main() {
    if let Err(e) = cli::run() {
        ui::log_structured_error(&e);
        std::process::exit(1);
    }
}
