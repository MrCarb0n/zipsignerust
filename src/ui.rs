/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::{APP_AUTHOR, APP_NAME, APP_VERSION};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::{Arc, Mutex};

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

    pub fn show_progress_bar(&self, len: u64, message: &str) {
        let pb = ProgressBar::new(len);
        let term_width = self.get_terminal_width();
        let max_width = if term_width > 0 { term_width } else { 80 };
        let effective_message = if max_width < 60 && message.chars().count() > 15 {
            let truncated_msg: String = message.chars().take(15).collect();
            format!("{}...", truncated_msg)
        } else {
            message.to_string()
        };

        let template = format!(
            "{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}} ({{eta}})",
            effective_message
        );

        let style = ProgressStyle::default_bar()
            .template(&template)
            .unwrap_or_else(|_| {
                let fallback_template = format!(
                    "{{spinner:.green}} {} {{bar:5.green}} {{pos}}/{{len}} ({{eta}})",
                    effective_message
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

    pub fn update_progress(&self, pos: u64) {
        let _ = self.progress_bar.lock().map(|g| {
            if let Some(ref pb) = *g {
                pb.set_position(pos);
            }
        });
    }

    pub fn finish_progress(&self) {
        let _ = self.progress_bar.lock().map(|g| {
            if let Some(ref pb) = *g {
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

    fn paint(&self, icon: &str, msg: &str, color: &str, _is_error: bool, is_dim: bool) {
        if self.silent && !_is_error {
            return;
        }

        let wrapped_content = self.format_message_with_wrap(msg, 0);
        let wrapped_lines: Vec<&str> = wrapped_content.split('\n').collect();
        let indent = " ".repeat(icon.len() + 1);

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
                    } else if is_dim {
                        format!("{}{}", indent, line.dimmed())
                    } else {
                        format!("{}{}", indent, line.normal())
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

    fn format_message_with_wrap(&self, message: &str, indent: usize) -> String {
        let max_width = std::env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
            .unwrap_or(80);

        let effective_width = max_width.saturating_sub(indent).max(10);
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

    fn get_terminal_width(&self) -> usize {
        std::env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or_else(|| terminal_size::terminal_size().map(|(w, _)| w.0 as usize))
            .unwrap_or(80)
    }
}
