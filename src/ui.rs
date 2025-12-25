// ZipSigner Rust - High-performance, memory-safe cryptographic signing and verification for Android ZIP archives
// Copyright (C) 2025 Tiash H Kabir / @MrCarb0n
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::{APP_AUTHOR, APP_NAME, APP_VERSION};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::{Arc, Mutex};

pub struct Ui {
    pub verbose: bool,
    pub very_verbose: bool,
    pub debug: bool,
    silent: bool,
    colors: bool,
    progress_bar: Arc<Mutex<Option<ProgressBar>>>,
    is_bytes_progress: Arc<Mutex<bool>>,
    temp_files: Arc<Mutex<Vec<std::path::PathBuf>>>,
}

impl Default for Ui {
    fn default() -> Self {
        Self::new(false, false, false, false, true)
    }
}

impl Ui {
    pub fn new(v: bool, vv: bool, d: bool, s: bool, c: bool) -> Self {
        Self {
            verbose: v,
            very_verbose: vv,
            debug: d,
            silent: s,
            colors: c,
            progress_bar: Arc::new(Mutex::new(None)),
            is_bytes_progress: Arc::new(Mutex::new(false)),
            temp_files: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn from_verbosity_level(level: u8, s: bool, c: bool) -> Self {
        Self::new(level >= 1, level >= 2, level >= 3, s, c)
    }

    pub fn show_progress_bar(&self, len: u64, msg: &str) {
        let pb = ProgressBar::new(len);
        let tw = self.term_width();
        let effective_msg = Self::truncate_msg(msg, tw);

        // For Termux compatibility, adjust the bar width to prevent right-side spacing
        // (not needed anymore since we use wide_bar which auto-expands)

        let template = if tw < 60 {
            format!(
                "{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}}",
                effective_msg
            )
        } else {
            format!(
                "{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}} ({{eta}})",
                effective_msg
            )
        };

        let style = ProgressStyle::default_bar()
            .template(&template)
            .unwrap_or_else(|_| {
                ProgressStyle::default_bar()
                    .template(&if tw < 60 {
                        format!(
                            "{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}}",
                            effective_msg
                        )
                    } else {
                        format!(
                            "{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}} ({{eta}})",
                            effective_msg
                        )
                    })
                    .unwrap_or_else(|_| {
                        ProgressStyle::default_bar()
                            .template(&format!("{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}}", effective_msg))
                            .unwrap()
                    })
            })
            .tick_strings(&["[|]", "[/]", "[-]", "[\\]"])
            .progress_chars("#>-");

        pb.set_style(style);
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        if let Ok(mut g) = self.progress_bar.lock() {
            *g = Some(pb);
        }
    }

    pub fn record_temp_file(&self, path: &std::path::Path) {
        if self.debug {
            if let Ok(mut files) = self.temp_files.lock() {
                files.push(path.to_path_buf());
                self.debug(&format!("Recorded: {:?}", path));
            }
        }
    }

    pub fn print_temp_files(&self) {
        if self.debug {
            if let Ok(files) = self.temp_files.lock() {
                if !files.is_empty() {
                    self.info(&format!("Files: {} item(s)", files.len()));
                    for path in files.iter() {
                        self.debug(&format!("  - {:?}", path));
                    }
                }
            }
        }
    }

    fn truncate_msg(msg: &str, tw: usize) -> String {
        let max_chars = if tw < 60 {
            8
        } else if tw < 80 {
            15
        } else {
            usize::MAX
        };
        if msg.chars().count() > max_chars {
            format!("{}...", msg.chars().take(max_chars).collect::<String>())
        } else {
            msg.to_string()
        }
    }

    fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        if bytes == 0 {
            return "0B".to_string();
        }

        let mut size = bytes as f64;
        let mut unit_idx = 0;

        while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }

        if unit_idx == 0 {
            // For bytes, just show the integer value
            format!("{}{}", bytes, UNITS[unit_idx])
        } else {
            // For larger units, show with one decimal place if needed
            if size.fract() < 0.01 {  // If fractional part is very small, show as integer
                format!("{:.0}{}", size, UNITS[unit_idx])
            } else {
                format!("{:.1}{}", size, UNITS[unit_idx])
            }
        }
    }

    pub fn show_detailed_progress_bar(&self, len: u64, msg: &str, unit: &str) {
        let pb = ProgressBar::new(len);
        let tw = self.term_width();
        let effective_msg = Self::truncate_msg(msg, tw);

        // For Termux compatibility, adjust the bar width to prevent right-side spacing
        // (not needed anymore since we use wide_bar which auto-expands)

        let template = if tw < 60 {
            if unit == "bytes" {
                format!(
                    "{{spinner:.green}} {} {{wide_bar:.green/red}} ({{msg}}) ({{eta}})",
                    effective_msg
                )
            } else {
                format!(
                    "{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}}",
                    effective_msg
                )
            }
        } else if tw < 80 {
            if unit == "bytes" {
                format!(
                    "{{spinner:.green}} {} {{wide_bar:.green/red}} ({{msg}}) ({{eta}})",
                    effective_msg
                )
            } else {
                format!(
                    "{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}} [{{percent}}%]",
                    effective_msg
                )
            }
        } else if unit == "bytes" {
            format!("{{spinner:.green}} {} {{wide_bar:.green/red}} ({{msg}}) ({{eta}})", effective_msg)
        } else {
            format!("{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}} ({{eta}}) [{{percent}}%]", effective_msg)
        };

        let style = ProgressStyle::default_bar()
            .template(&template)
            .unwrap_or_else(|_| {
                let ft = if tw < 60 {
                    if unit == "bytes" {
                        format!("{{spinner:.green}} {} {{wide_bar:.green}} ({{msg}})", effective_msg)
                    } else {
                        format!("{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}}", effective_msg)
                    }
                } else if unit == "bytes" {
                    format!("{{spinner:.green}} {} {{wide_bar:.green}} ({{msg}}) ({{eta}})", effective_msg)
                } else {
                    format!("{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}} ({{eta}})", effective_msg)
                };
                ProgressStyle::default_bar().template(&ft).unwrap_or_else(|_| {
                    ProgressStyle::default_bar()
                        .template(&format!("{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}}", effective_msg))
                        .unwrap()
                })
            })
            .tick_strings(&["[|]", "[/]", "[-]", "[\\]"])
            .progress_chars("#>-");

        pb.set_style(style);
        pb.enable_steady_tick(std::time::Duration::from_millis(120));

        // Set the progress bar message to include formatted byte information
        if unit == "bytes" {
            pb.set_message(format!("{}", Self::format_bytes(pb.position())));
        }

        // Set the bytes progress flag
        if let Ok(mut is_bytes) = self.is_bytes_progress.lock() {
            *is_bytes = unit == "bytes";
        }

        if let Ok(mut g) = self.progress_bar.lock() {
            *g = Some(pb);
        }
    }

    pub fn update_progress(&self, pos: u64) {
        let _ = self.progress_bar.lock().map(|g| {
            if let Some(ref pb) = *g {
                pb.set_position(pos);

                // Update the message to show formatted bytes if this is a bytes progress bar
                if let Ok(is_bytes) = self.is_bytes_progress.lock() {
                    if *is_bytes {
                        // Get the total from the progress bar's length
                        let total = pb.length().unwrap_or(0);
                        pb.set_message(format!("{} / {}", Self::format_bytes(pos), Self::format_bytes(total)));
                    }
                }
            }
        });
    }

    pub fn finish_progress(&self) {
        let _ = self.progress_bar.lock().map(|g| {
            if let Some(ref pb) = *g {
                // Update the message to show final formatted bytes if this is a bytes progress bar
                if let Ok(is_bytes) = self.is_bytes_progress.lock() {
                    if *is_bytes {
                        let total = pb.length().unwrap_or(0);
                        pb.set_message(format!("{} / {}", Self::format_bytes(total), Self::format_bytes(total)));
                    }
                }
                pb.finish_and_clear();
            }
        });
    }

    pub fn has_progress_bar(&self) -> bool {
        self.progress_bar
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    fn paint(&self, icon: &str, msg: &str, color: &str, is_error: bool, is_dim: bool) {
        if self.silent && !is_error {
            return;
        }
        // Use consistent indentation regardless of terminal width
        let indent_size = 4; // Consistent 4-space indentation
        let indent = " ".repeat(indent_size);
        let wrapped = self.wrap_msg(msg, indent_size);
        let lines: Vec<&str> = wrapped.split('\n').collect();

        let output_lines: Vec<String> = if self.supports_color() {
            let ic = match color {
                "31" => icon.red().bold().to_string(),
                "32" => icon.green().bold().to_string(),
                "33" => icon.yellow().bold().to_string(),
                "34" => icon.blue().bold().to_string(),
                "36" => icon.cyan().bold().to_string(),
                _ => icon.bold().to_string(),
            };
            lines
                .iter()
                .enumerate()
                .map(|(i, line)| {
                    if i == 0 {
                        if is_dim {
                            format!("{} {}", ic.dimmed(), line.dimmed())
                        } else {
                            format!("{} {}", ic, line.normal())
                        }
                    } else if is_dim {
                        format!("{}{}", indent, line.dimmed())
                    } else {
                        format!("{}{}", indent, line.normal())
                    }
                })
                .collect()
        } else {
            lines
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

        for line in output_lines {
            eprintln!("{}", line);
        }
    }

    pub fn print_banner(&self) {
        if !self.silent && self.verbose {
            self.print_rich_banner();
        }
    }

    pub fn print_rich_banner(&self) {
        let title = format!(" {} v{} ", APP_NAME, APP_VERSION);
        let width = title.len();
        let tw = self.term_width();

        if tw < width + 4 {
            if self.colors {
                eprintln!("{}", title.cyan().bold());
            } else {
                eprintln!("{}", title);
            }
        } else {
            let border = "-".repeat(width);
            if self.colors {
                let tb = format!("+-{}-+", border).magenta().bold();
                let mid = format!("| {} |", title.cyan().bold()).blue();
                eprintln!("{}\n{}\n{}", tb, mid, tb);
            } else {
                eprintln!("+-{}-+\n| {} |\n+-{}-+", border, title, border);
            }
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
            println!("{}", "License:     GPLv3".green());
            println!(
                "{}",
                "Description: High-performance cryptographic signer.".magenta()
            );
        } else {
            println!("Author:      {}\nRepository:  https://github.com/MrCarb0n/zipsignerust\nLicense:     GPLv3\nDescription: High-performance cryptographic signer.", APP_AUTHOR);
        }
    }

    pub fn supports_color(&self) -> bool {
        std::env::var("NO_COLOR").is_err() && self.colors && {
            #[cfg(windows)]
            {
                if !colored::control::SHOULD_COLORIZE.should_colorize() {
                    colored::control::set_override(true);
                }
            }
            true
        }
    }

    pub fn enable_colors_if_supported(&mut self) {
        #[cfg(windows)]
        if self.colors {
            colored::control::set_override(true);
        }
    }

    pub fn print_mode_header(&self, title: &str) {
        if self.silent || !self.verbose {
            return;
        }
        eprintln!();
        let header = format!("-- {} --", title);
        let tw = self.term_width();
        if tw < header.len() {
            if self.colors {
                eprintln!("{}", title.yellow().bold());
            } else {
                eprintln!("{}", title);
            }
        } else if self.colors {
            eprintln!("{}", header.yellow().bold());
        } else {
            eprintln!("{}", header);
        }
    }

    pub fn info(&self, msg: &str) {
        // Show for -v and higher (level 1+) - corresponds to info level
        if self.verbose {
            self.paint("[i]", msg, "34", false, false);
        }
    }
    pub fn debug(&self, msg: &str) {
        // Show for -vv and higher (level 2+) - corresponds to debug level
        if self.very_verbose {
            self.paint("[d]", msg, "2", false, true);
        }
    }
    pub fn trace(&self, msg: &str) {
        // Show for -vvv and higher (level 3+) - corresponds to trace level
        if self.debug {
            self.paint("[t]", msg, "2", false, true);
        }
    }
    pub fn success(&self, msg: &str) {
        if !self.silent {
            self.paint("[+]", msg, "32", false, false);
        }
    }
    pub fn warn(&self, msg: &str) {
        if !self.silent {
            self.paint("[!]", msg, "33", true, false);
        }
    }
    pub fn error(&self, msg: &str) {
        self.paint("[x]", msg, "31", true, false);
    }

    /// Print a section header with consistent styling
    pub fn print_section_header(&self, title: &str) {
        if self.colors {
            eprintln!("{}", format!("{}:", title).green().bold());
        } else {
            eprintln!("{}:", title);
        }
    }

    /// Print a help item with standardized formatting
    pub fn print_help_item(&self, command: &str, description: &str) {
        const COLUMN_WIDTH: usize = 18; // Fixed width for command column
        let padded_command = format!("  {:<width$}", command, width = COLUMN_WIDTH - 2);

        // Calculate the indent for wrapped lines
        let indent_size = COLUMN_WIDTH;

        // Wrap the description using UI's wrap_msg function with the calculated indent
        let wrapped_description = self.wrap_msg(description, indent_size);

        // Split the wrapped text into lines
        let lines: Vec<&str> = wrapped_description.split('\n').collect();

        for (i, line) in lines.iter().enumerate() {
            if i == 0 {
                // First line: padded command + first part of description
                if self.colors {
                    eprintln!("{}{}", padded_command, line.normal());
                } else {
                    eprintln!("{}{}", padded_command, line);
                }
            } else {
                // Subsequent lines: align with the description start column
                let indent = " ".repeat(indent_size);
                if self.colors {
                    eprintln!("{}{}", indent, line.normal());
                } else {
                    eprintln!("{}{}", indent, line);
                }
            }
        }
    }

    /// Print a help section with multiple items
    pub fn print_help_section(&self, title: &str, items: &[(&str, &str)]) {
        self.print_section_header(title);
        for (command, description) in items {
            self.print_help_item(command, description);
        }
        eprintln!();
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
            let base_indent = 4; // Consistent 4-space indentation like other UI elements
            let wrapped = self.wrap_msg(val, base_indent);
            let lines: Vec<&str> = wrapped.split('\n').collect();

            for (i, line) in lines.iter().enumerate() {
                if i == 0 {
                    if self.colors {
                        eprintln!("    {}: {}", key.cyan().bold(), line.green());
                    } else {
                        eprintln!("    {}: {}", key, line);
                    }
                } else if self.colors {
                    eprintln!("{}{}", " ".repeat(base_indent), line.green());
                } else {
                    eprintln!("{}{}", " ".repeat(base_indent), line);
                }
            }
        }
    }

    pub fn wrap_msg(&self, msg: &str, indent: usize) -> String {
        let max_width = self.term_width();
        let effective_width = if max_width > 20 {
            max_width.saturating_sub(indent).max(20)
        } else {
            max_width.saturating_sub(indent).max(10)
        };
        let mut lines = Vec::new();
        let mut current_line = String::with_capacity(effective_width);

        for word in msg.split_whitespace() {
            let word_len = word.chars().count();
            let needed = if current_line.is_empty() {
                word_len
            } else {
                current_line.chars().count() + 1 + word_len
            };

            if needed <= effective_width {
                if !current_line.is_empty() {
                    current_line.push(' ');
                }
                current_line.push_str(word);
            } else {
                if !current_line.is_empty() {
                    lines.push(std::mem::take(&mut current_line));
                }
                if word_len > effective_width {
                    let chunks: Vec<String> = word
                        .chars()
                        .collect::<Vec<_>>()
                        .chunks(effective_width)
                        .map(|c| c.iter().collect())
                        .collect();
                    for (i, chunk) in chunks.iter().enumerate() {
                        if i == 0 {
                            current_line.push_str(chunk);
                        } else {
                            lines.push(std::mem::take(&mut current_line));
                            current_line.push_str(chunk);
                        }
                    }
                } else {
                    current_line.push_str(word);
                }
            }
        }
        if !current_line.is_empty() {
            lines.push(current_line);
        }
        lines.join("\n")
    }

    fn term_width(&self) -> usize {
        std::env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
            .or_else(|| {
                #[cfg(unix)]
                if let Ok(output) = std::process::Command::new("tput").arg("cols").output() {
                    if !output.stdout.is_empty() {
                        if let Ok(cols_str) = String::from_utf8(output.stdout) {
                            if let Ok(width) = cols_str.trim().parse::<usize>() {
                                return Some(width);
                            }
                        }
                    }
                }
                None
            })
            .unwrap_or(80)
    }
}
