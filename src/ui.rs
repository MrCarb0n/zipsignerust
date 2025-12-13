/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::{APP_AUTHOR, APP_NAME, APP_VERSION};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::{Arc, Mutex};
use terminal_size::{terminal_size, Width};

// ANSI Color Codes
const COLOR_RED: &str = "31";
const COLOR_GREEN: &str = "32";
const COLOR_YELLOW: &str = "33";
const COLOR_BLUE: &str = "34";
const COLOR_CYAN: &str = "36";
const COLOR_DIM: &str = "2";
const MAX_TERMINAL_WIDTH: u16 = 80; // Threshold for narrow terminals

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

    /// Detect if we're in a narrow terminal
    pub fn is_narrow_terminal(&self) -> bool {
        terminal_size()
            .map(|(Width(w), _)| w < MAX_TERMINAL_WIDTH)
            .unwrap_or(false)
    }

    /// Get the current terminal width, with fallback
    pub fn get_terminal_width(&self) -> u16 {
        terminal_size()
            .map(|(Width(w), _)| w)
            .unwrap_or(80)
    }

    /// Creates and shows a progress bar with the specified style
    pub fn show_progress_bar(&self, len: u64, message: &str) {
        let pb = ProgressBar::new(len);

        // Adjust progress bar width based on terminal width
        let bar_width = if self.is_narrow_terminal() {
            std::cmp::min(20, self.get_terminal_width().saturating_sub(30) as usize)
        } else {
            40
        };

        let template = if self.is_narrow_terminal() {
            // Simplified version for narrow terminals
            format!("{{spinner:.green}} [{{elapsed_precise}}] {{bar:{bar_width}}} {{pos}}/{{len}}", bar_width = bar_width)
        } else {
            format!(
                "{{spinner:.green}} [{{elapsed_precise}}] {} {{bar:{bar_width}.cyan/blue}} {{pos}}/{{len}} ({{eta}})",
                message,
                bar_width = bar_width
            )
        };

        pb.set_style(
            ProgressStyle::default_bar()
                .template(&template)
                .unwrap(),
        );
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
        let border = if self.is_narrow_terminal() {
            // For narrow terminals, don't make the border wider than the terminal
            let terminal_width = self.get_terminal_width() as usize;
            let max_border_width = std::cmp::min(width, terminal_width.saturating_sub(4));
            "-".repeat(max_border_width)
        } else {
            "-".repeat(width)
        };

        // Print empty line first to separate from any piped output
        eprintln!();

        if self.is_narrow_terminal() {
            // For narrow terminals, use a simpler banner
            eprintln!("{}", title.trim().cyan().bold());
        } else if self.colors {
            let top_bottom = format!("+-{}-+", border).cyan();
            let middle = format!("| {} |", title.cyan().bold()).cyan();
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
        eprintln!();
        println!("Author:      {}", APP_AUTHOR);
        println!("Repository:  https://github.com/MrCarb0n/zipsignerust");
        println!("License:     MIT");
        println!("Description: High-performance cryptographic signer.");
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
        if self.is_narrow_terminal() {
            // On narrow terminals, use a simpler header
            if self.colors {
                eprintln!("\n> {}", title.bold());
            } else {
                eprintln!("\n> {}", title);
            }
        } else if self.colors {
            eprintln!("\n{}", format!("-- {} --", title).dimmed());
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
            eprintln!("{}", format!("{}:", title).bold());
        } else {
            eprintln!("{}:", title);
        }

        for (key, val) in fields {
            if self.is_narrow_terminal() {
                // On narrow terminals, use a more compact format
                eprintln!("{}: {}", key, val);
            } else if self.colors {
                eprintln!("  {:<15} {}", key.cyan(), val);
            } else {
                eprintln!("  {:<15} {}", key, val);
            }
        }
        eprintln!();
    }

    /// Prints an info message using colored crate
    pub fn info_colored(&self, msg: &str) {
        if !self.verbose {
            return;
        }
        if self.colors {
            eprintln!("{}", format!("[INFO] {}", msg).blue().bold());
        } else {
            eprintln!("[INFO] {}", msg);
        }
    }

    /// Prints a success message using colored crate
    pub fn success_colored(&self, msg: &str) {
        if self.silent {
            return;
        }
        if self.colors {
            eprintln!("{}", format!("[SUCCESS] {}", msg).green().bold());
        } else {
            eprintln!("[SUCCESS] {}", msg);
        }
    }

    /// Prints a warning message using colored crate
    pub fn warn_colored(&self, msg: &str) {
        if self.silent {
            return;
        }
        if self.colors {
            eprintln!("{}", format!("[WARN] {}", msg).yellow().bold());
        } else {
            eprintln!("[WARN] {}", msg);
        }
    }

    /// Prints an error message using colored crate
    pub fn error_colored(&self, msg: &str) {
        eprintln!("{}", format!("[ERROR] {}", msg).red().bold());
    }

    /// Prints a debug message when in verbose mode
    pub fn debug(&self, msg: &str) {
        if self.verbose {
            if self.colors {
                eprintln!("{}", format!("[DEBUG] {}", msg).purple().dimmed());
            } else {
                eprintln!("[DEBUG] {}", msg);
            }
        }
    }

    /// Prints a formatted table from Vec<&str> rows
    pub fn print_table(&self, headers: &[&str], rows: Vec<Vec<String>>) {
        if self.is_narrow_terminal() {
            // For narrow terminals, use a simpler format
            for row in rows {
                for (i, cell) in row.iter().enumerate() {
                    if i < headers.len() {
                        println!("{}: {}", headers[i], cell);
                    } else {
                        println!("{}: {}", i, cell);
                    }
                }
                println!(); // blank line between rows
            }
        } else if self.colors {
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

        if self.is_narrow_terminal() {
            // For narrow terminals, use a simpler format
            for (key, value) in data {
                println!("{}: {}", key, value);
            }
        } else if self.colors {
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
                println!("{:<20} : {}", key, value);
            }
        }
    }
}
