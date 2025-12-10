/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::{APP_AUTHOR, APP_NAME, APP_VERSION};

// ANSI Color Codes
const COLOR_RED: &str = "31";
const COLOR_GREEN: &str = "32";
const COLOR_YELLOW: &str = "33";
const COLOR_BLUE: &str = "34";
const COLOR_CYAN: &str = "36";
const COLOR_DIM: &str = "2";
const COLOR_BOLD: &str = "1";

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

    fn paint(&self, icon: &str, msg: &str, color: &str, _is_error: bool, is_dim: bool) {
        if self.silent && !_is_error {
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

        eprintln!("{}", formatted);
    }

    pub fn print_banner(&self) {
        if self.silent || !self.verbose {
            return;
        }
        self.print_rich_banner();
    }

    pub fn print_rich_banner(&self) {
        let title = format!(" {} v{} ", APP_NAME, APP_VERSION);
        let width = title.len();
        let border = "-".repeat(width);

        // Print empty line first to separate from any piped output
        eprintln!();

        if self.colors {
            eprintln!("\x1b[{}m+-{}-+\x1b[0m", COLOR_CYAN, border);
            eprintln!(
                "\x1b[{}m| \x1b[{}m{}\x1b[{}m |\x1b[0m",
                COLOR_CYAN, COLOR_BOLD, title, COLOR_CYAN
            );
            eprintln!("\x1b[{}m+-{}-+\x1b[0m", COLOR_CYAN, border);
        } else {
            eprintln!("+-{}-+", border);
            eprintln!("| {} |", title);
            eprintln!("+-{}-+", border);
        }
    }

    pub fn print_version_info(&self) {
        self.print_rich_banner();
        eprintln!();
        println!("Author:      {}", APP_AUTHOR);
        println!("Repository:  https://github.com/MrCarb0n/zipsignerust");
        println!("License:     MIT");
        println!("Description: High-performance cryptographic signer.");
    }

    pub fn print_mode_header(&self, title: &str) {
        if self.silent || !self.verbose {
            return;
        }
        if self.colors {
            eprintln!("\n\x1b[{}m-- {} --\x1b[0m", COLOR_DIM, title);
        } else {
            eprintln!("\n-- {} --", title);
        }
    }

    pub fn info(&self, msg: &str) {
        if !self.verbose {
            return;
        }
        self.paint("[i]", msg, COLOR_BLUE, false, false);
    }

    pub fn verbose(&self, msg: &str) {
        if self.verbose {
            self.paint("[v]", msg, COLOR_DIM, false, true);
        }
    }

    pub fn success(&self, msg: &str) {
        if self.silent {
            return;
        }
        self.paint("[+]", msg, COLOR_GREEN, false, false);
    }

    pub fn warn(&self, msg: &str) {
        if self.silent {
            return;
        }
        self.paint("[!]", msg, COLOR_YELLOW, true, false);
    }

    pub fn error(&self, msg: &str) {
        self.paint("[x]", msg, COLOR_RED, true, false);
    }

    pub fn print_summary(&self, title: &str, fields: &[(&str, String)]) {
        if self.silent || !self.verbose {
            return;
        }
        eprintln!();
        if self.colors {
            eprintln!("\x1b[1m{}:\x1b[0m", title);
        } else {
            eprintln!("{}:", title);
        }

        for (key, val) in fields {
            eprintln!("  {:<15} {}", key, val);
        }
        eprintln!();
    }
}
