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

        // Get terminal width to calculate appropriate progress bar size
        let term_width = self.get_terminal_width();
        let max_width = if term_width > 0 { term_width } else { 80 };

        // Calculate expected lengths of other components in the template
        // Format: {spinner:.green} [elapsed_precise] message {bar:width.green/red} pos/len (eta)
        let pos_len = len.to_string().len();
        let position_display_len = 2 * pos_len + 1; // for "123/456" format (~2*len + 1 for separator)

        // Determine an appropriate message length for narrow screens
        let effective_message = if max_width < 60 && message.chars().count() > 15 {
            // For narrow screens, truncate message if it's too long using char boundaries
            let truncated_msg: String = message.chars().take(15).collect();
            format!("{}...", truncated_msg)
        } else {
            message.to_string()
        };

        // Calculate space needed for other elements in the format:
        // {spinner:.green} [elapsed_precise] message {wide_bar:.green/red} pos/len (eta)
        let spinner_space = 3;        // "~ " + space
        let time_space = 13;          // "[00:00:01]" + space
        let message_space = effective_message.len() + 1;  // message + space
        let position_space = position_display_len + 1;    // "1234/5678" + space
        let eta_space = 9;            // "(~99m)" + space

        let total_reserved_space = spinner_space + time_space + message_space + position_space + eta_space;

        let bar_width = if max_width > total_reserved_space {
            max_width - total_reserved_space
        } else {
            // For very narrow terminals, calculate a minimal but usable bar width
            let minimal_bar_width = if max_width > 20 {
                5  // Reasonable bar width when terminal is 20+ chars
            } else if max_width > 15 {
                3  // Minimal bar when terminal is 15-20 chars
            } else {
                1  // Absolute minimum when terminal is extremely narrow
            };
            minimal_bar_width
        }
        .max(1); // Ensure minimum 1 character for the bar to be visible

        // Use a template that adapts to terminal width with ASCII characters
        // Use wide format that automatically fills available space
        let template = format!(
            "{{spinner:.green}} [{{elapsed_precise}}] {} {{wide_bar:.green/red}} {{pos}}/{{len}} ({{eta}})",
            effective_message
        );

        // Use a fallback template if the custom template fails
        let style = ProgressStyle::default_bar()
            .template(&template)
            .unwrap_or_else(|_| {
                // Fallback to fixed-width if wide_bar doesn't work
                let fallback_template = format!(
                    "{{spinner:.green}} [{{elapsed_precise}}] {} {{bar:{}.green}} {{pos}}/{{len}} ({{eta}})",
                    effective_message,
                    bar_width
                );
                ProgressStyle::default_bar()
                    .template(&fallback_template)
                    .expect("Fallback template should always be valid")
            })
            // Customize the progress bar to use ASCII characters instead of Unicode
            .progress_chars("#>-");

        pb.set_style(style);
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

        // Format long messages with nice wrapping (without the indentation added here)
        let wrapped_content = self.format_message_with_wrap(msg, 0);
        let wrapped_lines: Vec<&str> = wrapped_content.split('\n').collect();

        if self.supports_color() {
            let icon_colored = self.colored_icon(icon, color);

            for (i, line) in wrapped_lines.iter().enumerate() {
                if i == 0 {
                    // First line has icon
                    let line_output = if is_dim {
                        format!("{} {}", icon_colored.dimmed(), line.dimmed())
                    } else {
                        format!("{} {}", icon_colored, line.normal())
                    };
                    eprintln!("{}", line_output);
                } else {
                    // Subsequent lines have indentation equal to icon length + space
                    let indent = " ".repeat(icon.len() + 1); // +1 for the space after icon
                    let line_output = if is_dim {
                        format!("{}{}", indent, line.dimmed())
                    } else {
                        format!("{}{}", indent, line.normal())
                    };
                    eprintln!("{}", line_output);
                }
            }
        } else {
            for (i, line) in wrapped_lines.iter().enumerate() {
                if i == 0 {
                    // First line has icon
                    eprintln!("{} {}", icon, line);
                } else {
                    // Subsequent lines have indentation equal to icon length + space
                    let indent = " ".repeat(icon.len() + 1); // +1 for the space after icon
                    eprintln!("{}{}", indent, line);
                }
            }
        }
    }

    /// Helper function to create colored icons
    fn colored_icon(&self, icon: &str, color: &str) -> String {
        match color {
            COLOR_RED => icon.red().bold().to_string(),     // Red
            COLOR_GREEN => icon.green().bold().to_string(), // Green
            COLOR_YELLOW => icon.yellow().bold().to_string(), // Yellow
            COLOR_BLUE => icon.blue().bold().to_string(),   // Blue
            COLOR_CYAN => icon.cyan().bold().to_string(),   // Cyan
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
            let formatted_val = self.format_message_with_wrap(val, key.len() + 10); // 2 spaces + 8 from {:<8}

            // Split and properly format with indentation
            let value_lines: Vec<String> =
                formatted_val.split('\n').map(|s| s.to_string()).collect();

            for (i, line) in value_lines.iter().enumerate() {
                if i == 0 {
                    if self.colors {
                        eprintln!("  {:<8} {}", key.cyan().bold(), line.as_str().green());
                    } else {
                        eprintln!("  {:<8} {}", key, line.as_str());
                    }
                } else {
                    let indent = " ".repeat(key.len() + 10); // Match the field alignment
                    if self.colors {
                        eprintln!("{}{}", indent, line.as_str().green());
                    } else {
                        eprintln!("{}{}", indent, line.as_str());
                    }
                }
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
                let formatted_val = self.format_message_with_wrap(value, key.len() + 10); // 8 from {:<8} + 2 for " : "

                // Split and properly format with indentation
                let value_lines: Vec<String> =
                    formatted_val.split('\n').map(|s| s.to_string()).collect();

                for (i, line) in value_lines.iter().enumerate() {
                    if i == 0 {
                        println!("{:<8} : {}", key, line.as_str());
                    } else {
                        let indent = " ".repeat(key.len() + 10); // Match the field alignment
                        println!("{}  {}", indent, line.as_str());
                    }
                }
            }
        }
    }

    /// Format and wrap long text messages with proper indentation
    pub fn format_message_with_wrap(&self, message: &str, indent: usize) -> String {
        // Get terminal width if available, default to 80 if not
        let term_width = self.get_terminal_width();
        let max_width = if term_width > 0 { term_width } else { 80 };

        let effective_width = if max_width > indent {
            max_width - indent
        } else {
            80 - indent
        };

        let mut lines = Vec::with_capacity(4); // Pre-allocate for efficiency
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
                // Add the current line to lines before starting a new one
                if !current_line.is_empty() {
                    lines.push(std::mem::take(&mut current_line)); // Use std::mem::take to move the value out
                }

                // Start new line with this word if it fits in a single line
                if word.len() <= effective_width {
                    current_line.push_str(word);
                } else {
                    // If the word is too long for a single line, break it
                    let mut word_chars = word.chars();
                    let chunk = word_chars.by_ref().take(effective_width).collect::<String>();
                    lines.push(chunk);
                    // Handle remaining part of the long word
                    let remaining: String = word_chars.collect();
                    if !remaining.is_empty() {
                        current_line.push_str(&remaining);
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
        // Try to use term_size if available, otherwise default to 80
        match std::env::var("COLUMNS") {
            Ok(columns_str) => columns_str.parse().unwrap_or(80),
            Err(_) => {
                // Fallback to using the term_size crate if available
                term_size::dimensions().map(|(w, _)| w).unwrap_or(80)
            }
        }
    }
}
