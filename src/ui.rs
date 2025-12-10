/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2024 Tiash / @MrCarb0n and Earth Inc.
 * Licensed under the MIT License.
 */

use crate::{APP_NAME, APP_VERSION};

// ANSI Color Codes
const COLOR_RED: &str = "31";
const COLOR_GREEN: &str = "32";
const COLOR_YELLOW: &str = "33";
const COLOR_BLUE: &str = "34";
const COLOR_DIM: &str = "2";

pub struct Ui {
    verbose: bool,
    silent: bool,
    colors: bool,
}

impl Default for Ui {
    fn default() -> Self {
        Self::new(false, false, true)
    }
}

impl Ui {
    pub fn new(verbose: bool, silent: bool, colors: bool) -> Self {
        Self {
            verbose,
            silent,
            colors,
        }
    }

    fn paint(&self, icon: &str, msg: &str, color: &str, is_error: bool, is_dim: bool) {
        if self.silent {
            return;
        }

        let formatted = if self.colors {
            let style = if is_dim {
                format!("\x1b[{}m", COLOR_DIM)
            } else {
                "".to_string()
            };
            format!("{}\x1b[{}m{}\x1b[0m {}", style, color, icon, msg)
        } else {
            format!("{} {}", icon, msg)
        };

        if is_error {
            eprintln!("{}", formatted);
        } else {
            println!("{}", formatted);
        }
    }

    pub fn print_banner(&self) {
        // Banner only shows in verbose mode
        if self.silent || !self.verbose {
            return;
        }
        let title = format!("{} v{}", APP_NAME, APP_VERSION);
        let width = title.len() + 4;
        let border = "-".repeat(width);
        
        println!("+{}+", border);
        println!("|  {}  |", title);
        println!("+{}+", border);
    }

    pub fn print_mode_header(&self, title: &str) {
        // Mode header only shows in verbose mode
        if self.silent || !self.verbose {
            return;
        }
        println!("\n-- {} --", title);
    }

    pub fn info(&self, msg: &str) {
        // Standard info: "[i]" in blue
        self.paint("[i]", msg, COLOR_BLUE, false, false);
    }

    pub fn verbose(&self, msg: &str) {
        // Verbose info: "[v]" in dim style, only if verbose is on
        if self.verbose {
            self.paint("[v]", msg, "0", false, true);
        }
    }

    pub fn success(&self, msg: &str) {
        self.paint("[+]", msg, COLOR_GREEN, false, false);
    }

    pub fn warn(&self, msg: &str) {
        self.paint("[!]", msg, COLOR_YELLOW, true, false);
    }

    pub fn error(&self, msg: &str) {
        self.paint("[x]", msg, COLOR_RED, true, false);
    }

    pub fn print_summary(&self, title: &str, fields: &[(&str, String)]) {
        if self.silent {
            return;
        }
        println!(); 
        if self.colors {
            println!("\x1b[1m{}:\x1b[0m", title);
        } else {
            println!("{}:", title);
        }
        
        for (key, val) in fields {
            println!("  {:<15} {}", key, val);
        }
        println!();
    }
}