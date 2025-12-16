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

        let term_width = self.get_terminal_width();
        let max_width = if term_width > 0 { term_width } else { 80 };

        let pos_len = len.to_string().len();
        let position_display_len = 2 * pos_len + 1;

        let effective_message = if max_width < 60 && message.chars().count() > 15 {
            let truncated_msg: String = message.chars().take(15).collect();
            format!("{}...", truncated_msg)
        } else {
            message.to_string()
        };

        let spinner_space = 3;
        let time_space = 0; // Removed elapsed timestamp since ETA shows remaining time
        let message_space = effective_message.len() + 1;
        let position_space = position_display_len + 1;
        let eta_space = 9;

        let total_reserved_space =
            spinner_space + time_space + message_space + position_space + eta_space;

        let bar_width = if max_width > total_reserved_space {
            max_width - total_reserved_space
        } else {
            if max_width > 20 {
                5
            } else if max_width > 15 {
                3
            } else {
                1
            }
        }
        .max(1);

        let template = format!(
            "{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}} ({{eta}})",
            effective_message
        );

        let style = ProgressStyle::default_bar()
            .template(&template)
            .unwrap_or_else(|_| {
                let fallback_template = format!(
                    "{{spinner:.green}} {} {{bar:{}.green}} {{pos}}/{{len}} ({{eta}})",
                    effective_message, bar_width
                );
                ProgressStyle::default_bar()
                    .template(&fallback_template)
                    .expect("Fallback template should always be valid")
            })
            .tick_strings(&["[|]", "[/]", "[-]", "[\\]"])
            .progress_chars("#>-");

        pb.set_style(style);
        pb.enable_steady_tick(std::time::Duration::from_millis(120));

        if let Ok(mut guard) = self.progress_bar.lock() {
            *guard = Some(pb);
        }
    }

    /// Updates the progress bar position
    pub fn update_progress(&self, pos: u64) {
        let _ = self.progress_bar.lock().map(|g| {
            if let Some(ref pb) = *g {
                pb.set_position(pos);
            }
        });
    }

    /// Finishes and hides the progress bar
    pub fn finish_progress(&self) {
        let _ = self.progress_bar.lock().map(|g| {
            if let Some(ref pb) = *g {
                pb.finish_and_clear();
            }
        });
    }

    /// Check if a progress bar exists
    pub fn has_progress_bar(&self) -> bool {
        self.progress_bar
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    fn paint(&self, icon: &str, msg: &str, color: &str, _is_error: bool, is_dim: bool) {
        if self.silent && !_is_error {
            return;
        }

        let wrapped_content = self.format_message_with_wrap(msg, 0);
        let wrapped_lines: Vec<&str> = wrapped_content.split('\n').collect();
        let icon_len = icon.len() + 1; // +1 for the space after icon
        let indent = " ".repeat(icon_len);

        let lines_with_prefix: Vec<String> = if self.supports_color() {
            let icon_colored = self.colored_icon(icon, color);
            wrapped_lines
                .iter()
                .enumerate()
                .map(|(i, line)| {
                    if i == 0 {
                        if is_dim {
                            format!("{} {}", icon_colored.dimmed(), line.dimmed())
                        } else {
                            format!("{} {}", icon_colored, line.normal())
                        }
                    } else {
                        if is_dim {
                            format!("{}{}", indent, line.dimmed())
                        } else {
                            format!("{}{}", indent, line.normal())
                        }
                    }
                })
                .collect()
        } else {
            wrapped_lines
                .iter()
                .enumerate()
                .map(|(i, line)| {
                    if i == 0 {
                        format!("{} {}", icon, line)
                    } else {
                        format!("{}{}", indent, line)
                    }
                })
                .collect()
        };

        for line in lines_with_prefix {
            eprintln!("{}", line);
        }
    }

    /// Helper function to create colored icons
    fn colored_icon(&self, icon: &str, color: &str) -> String {
        match color {
            COLOR_RED => icon.red().bold().to_string(),
            COLOR_GREEN => icon.green().bold().to_string(),
            COLOR_YELLOW => icon.yellow().bold().to_string(),
            COLOR_BLUE => icon.blue().bold().to_string(),
            COLOR_CYAN => icon.cyan().bold().to_string(),
            _ => icon.bold().to_string(),
        }
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
        if std::env::var("NO_COLOR").is_ok() || !self.colors {
            return false;
        }

        #[cfg(windows)]
        {
            if !colored::control::SHOULD_COLORIZE.should_colorize() {
                colored::control::set_override(true);
            }
        }

        true
    }

    /// Automatically enable color support if available
    pub fn enable_colors_if_supported(&mut self) {
        #[cfg(windows)]
        {
            if self.colors {
                colored::control::set_override(true);
            }
        }
    }

    pub fn print_mode_header(&self, title: &str) {
        if self.silent || !self.verbose {
            return;
        }
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
            let indent = " ".repeat(key.len() + 10);
            let wrapped_content = self.format_message_with_wrap(val, key.len() + 10);
            let wrapped_lines: Vec<&str> = wrapped_content.split('\n').collect();

            for (i, line) in wrapped_lines.iter().enumerate() {
                if i == 0 {
                    if self.colors {
                        eprintln!("  {:<8} {}", key.cyan().bold(), line.green());
                    } else {
                        eprintln!("  {:<8} {}", key, line);
                    }
                } else if self.colors {
                    eprintln!("{}{}", indent, line.green());
                } else {
                    eprintln!("{}{}", indent, line);
                }
            }
        }
    }

    /// Prints a formatted table from Vec<&str> rows
    pub fn print_table(&self, headers: &[&str], rows: Vec<Vec<String>>) {
        if self.colors {
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
                let formatted_val = self.format_message_with_wrap(value, key.len() + 10);

                let value_lines: Vec<String> =
                    formatted_val.split('\n').map(|s| s.to_string()).collect();

                for (i, line) in value_lines.iter().enumerate() {
                    if i == 0 {
                        println!("{:<8} : {}", key, line.as_str());
                    } else {
                        let indent = " ".repeat(key.len() + 10);
                        println!("{}  {}", indent, line.as_str());
                    }
                }
            }
        }
    }

    /// Format and wrap long text messages with proper indentation
    pub fn format_message_with_wrap(&self, message: &str, indent: usize) -> String {
        let term_width = self.get_terminal_width();
        let max_width = if term_width > 0 { term_width } else { 80 };
        let effective_width = max_width.saturating_sub(indent).max(10); // Minimum width of 10

        let mut lines = Vec::with_capacity(4);
        let mut current_line = String::with_capacity(effective_width);

        for word in message.split_whitespace() {
            let space_needed = if current_line.is_empty() {
                word.len()
            } else {
                current_line.len() + 1 + word.len()
            };

            if space_needed <= effective_width {
                if !current_line.is_empty() {
                    current_line.push(' ');
                }
                current_line.push_str(word);
            } else {
                if !current_line.is_empty() {
                    lines.push(std::mem::take(&mut current_line));
                }

                if word.len() <= effective_width {
                    current_line.push_str(word);
                } else {
                    // Break long word into chunks
                    let mut chars = word.chars();
                    let chunk: String = chars.by_ref().take(effective_width).collect();
                    lines.push(chunk);
                    if let Some(remaining) = chars.as_str().into() {
                        current_line.push_str(remaining);
                    }
                }
            }
        }

        if !current_line.is_empty() {
            lines.push(current_line);
        }

        lines.join("\n")
    }

    /// Get the width of the terminal (or default to 80 if not available)
    fn get_terminal_width(&self) -> usize {
        std::env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or_else(|| term_size::dimensions().map(|(w, _)| w))
            .unwrap_or(80)
    }
}
