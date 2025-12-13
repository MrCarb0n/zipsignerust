/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2024 Tiash / @MrCarb0n and Earth Inc.
 * Licensed under the MIT License.
 * -----------------------
 * Main entry point for the application.
 */

use zipsignerust::cli;
use zipsignerust::ui::Ui;

fn main() {
    if let Err(e) = cli::run() {
        // Create a default UI just for logging the error cleanly
        let mut ui = Ui::default();
        ui.enable_colors_if_supported();
        ui.error(&format!("{}", e));
        std::process::exit(1);
    }
}
