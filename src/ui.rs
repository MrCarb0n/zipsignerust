/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::{APP_AUTHOR, APP_NAME, APP_VERSION};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::{Arc, Mutex};

// ANSI Color Codes
const COLOR_RED: &str = "31";
const COLOR_GREEN: &str = "32";
const COLOR_YELLOW: &str = "33";
const COLOR_BLUE: &str = "34";
const COLOR_CYAN: &str = "36";
const COLOR_DIM: &str = "2";

pub struct Ui {
    pub(crate) verbose: bool,
    silent: bool,
    colors: bool,
    progress_bar: Arc<Mutex<Option<ProgressBar>>>,
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
            progress_bar: Arc::new(Mutex::new(None)),
        }
    }

    /// Creates and shows a progress bar with the specified style
    pub fn show_progress_bar(&self, len: u64, message: &str) {
        let pb = ProgressBar::new(len);

        let bar_width = 40;

        let template = format!(
            "{{spinner:.green}} [{{elapsed_precise}}] {} {{bar:{bar_width}.cyan/blue}} {{pos}}/{{len}} ({{eta}})",
            message,
            bar_width = bar_width
        );

        pb.set_style(ProgressStyle::default_bar().template(&template).unwrap());
        pb.enable_steady_tick(std::time::Duration::from_millis(120));

        if let Ok(mut guard) = self.progress_bar.lock() {
            *guard = Some(pb);
        }
    }

    /// Updates the progress bar position
    pub fn update_progress(&self, pos: u64) {
        if let Ok(guard) = self.progress_bar.lock() {
            if let Some(ref pb) = *guard {
                pb.set_position(pos);
            }
        }
    }

    /// Finishes and hides the progress bar
    pub fn finish_progress(&self) {
        if let Ok(guard) = self.progress_bar.lock() {
            if let Some(ref pb) = *guard {
                pb.finish_and_clear();
            }
        }
    }

    /// Check if a progress bar exists
    pub fn has_progress_bar(&self) -> bool {
        if let Ok(guard) = self.progress_bar.lock() {
            guard.is_some()
        } else {
            false
        }
    }

    fn paint(&self, icon: &str, msg: &str, color: &str, _is_error: bool, is_dim: bool) {
        if self.silent && !_is_error {
            return;
        }

        let formatted = if self.supports_color() {
            let icon_colored = match color {
                COLOR_RED => icon.to_string().red().bold().to_string(), // Red
                COLOR_GREEN => icon.to_string().green().bold().to_string(), // Green
                COLOR_YELLOW => icon.to_string().yellow().bold().to_string(), // Yellow
                COLOR_BLUE => icon.to_string().blue().bold().to_string(), // Blue
                COLOR_CYAN => icon.to_string().cyan().bold().to_string(), // Cyan
                _ => icon.to_string().bold().to_string(),
            };

            if is_dim {
                format!("{} {}", icon_colored.dimmed(), msg.dimmed())
            } else {
                format!("{} {}", icon_colored, msg.normal())
            }
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

        if self.colors {
            let top_bottom = format!("+-{}-+", border).magenta().bold();
            let middle = format!("| {} |", title.cyan().bold()).blue();
            eprintln!("{}", top_bottom);
            eprintln!("{}", middle);
            eprintln!("{}", top_bottom);
        } else {
            eprintln!("+-{}-+", border);
            eprintln!("| {} |", title);
            eprintln!("+-{}-+", border);
        }
    }

    pub fn print_version_info(&self) {
        self.print_rich_banner();
        if self.colors {
            println!("{}", format!("Author:      {}", APP_AUTHOR).yellow());
            println!(
                "{}",
                "Repository:  https://github.com/MrCarb0n/zipsignerust".cyan()
            );
            println!("{}", "License:     MIT".green());
            println!(
                "{}",
                "Description: High-performance cryptographic signer.".magenta()
            );
        } else {
            println!("Author:      {}", APP_AUTHOR);
            println!("Repository:  https://github.com/MrCarb0n/zipsignerust");
            println!("License:     MIT");
            println!("Description: High-performance cryptographic signer.");
        }
    }

    fn supports_color(&self) -> bool {
        // Check NO_COLOR environment variable first
        if std::env::var("NO_COLOR").is_ok() {
            return false;
        }

        // Check if colors are explicitly disabled
        if !self.colors {
            return false;
        }

        // On Windows, check if terminal supports colors
        #[cfg(windows)]
        {
            if !colored::control::SHOULD_COLORIZE.should_colorize() {
                // Try to enable color support on Windows
                colored::control::set_override(true);
            }
        }

        true
    }

    /// Automatically enable color support if available
    pub fn enable_colors_if_supported(&mut self) {
        #[cfg(windows)]
        {
            // On Windows, enable color support
            if self.colors {
                colored::control::set_override(true);
            }
        }

        // On Unix systems, colors are typically supported by default
        // unless NO_COLOR is set
    }

    pub fn print_mode_header(&self, title: &str) {
        if self.silent || !self.verbose {
            return;
        }
        // Add spacing before mode header for better visual separation
        eprintln!();
        if self.colors {
            eprintln!("{}", format!("-- {} --", title).yellow().bold());
        } else {
            eprintln!("-- {} --", title);
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
        if self.colors {
            eprintln!("{}", format!("{}:", title).green().bold());
        } else {
            eprintln!("{}:", title);
        }

        for (key, val) in fields {
            if self.colors {
                eprintln!("  {:<8} {}", key.cyan().bold(), val.green());
            } else {
                eprintln!("  {:<8} {}", key, val);
            }
        }
    }

    /// Prints a formatted table from Vec<&str> rows
    pub fn print_table(&self, headers: &[&str], rows: Vec<Vec<String>>) {
        if self.colors {
            // Just print a formatted table for wider terminals
            let header_str = headers.join(" │ ");
            println!("{}", format!("┌─ {} ─┐", header_str).bold().bright_white());

            for row in rows {
                let row_str = row.join(" │ ");
                println!("├─ {} ─┤", row_str);
            }
            println!(
                "{}",
                "└─────────────────────────────────────────┘"
                    .bold()
                    .bright_white()
            );
        } else {
            println!("{}", headers.join(" | "));
            for row in rows {
                let row_str = row.join(" | ");
                println!("{}", row_str);
            }
        }
    }

    /// Print a simple key-value table
    pub fn print_key_value_table(&self, data: &[(&str, &str)]) {
        let rows: Vec<Vec<String>> = data
            .iter()
            .map(|(key, value)| vec![(*key).to_string(), (*value).to_string()])
            .collect();

        if self.colors {
            let header_str = "KEY │ VALUE".to_string();
            println!("{}", format!("┌─ {} ─┐", header_str).bold().bright_white());

            for row in rows {
                let row_str = format!(
                    "{} │ {}",
                    row.first().unwrap_or(&"".to_string()),
                    row.get(1).unwrap_or(&"".to_string())
                );
                println!("├─ {} ─┤", row_str);
            }
            println!(
                "{}",
                "└─────────────────────────────────────────┘"
                    .bold()
                    .bright_white()
            );
        } else {
            for (key, value) in data {
                println!("{:<8} : {}", key, value);
            }
        }
    }
}
