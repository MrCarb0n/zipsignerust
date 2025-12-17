/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

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
        let template = if tw < 60 {
            format!(
                "{{spinner:.green}} {} {{bar:.green/red}} {{pos}}/{{len}}",
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
                            "{{spinner:.green}} {} {{bar:5.green}} {{pos}}/{{len}}",
                            effective_msg
                        )
                    } else {
                        format!(
                            "{{spinner:.green}} {} {{bar:5.green}} {{pos}}/{{len}} ({{eta}})",
                            effective_msg
                        )
                    })
                    .expect("Valid template")
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

    pub fn show_detailed_progress_bar(&self, len: u64, msg: &str, unit: &str) {
        let pb = ProgressBar::new(len);
        let tw = self.term_width();
        let effective_msg = Self::truncate_msg(msg, tw);
        let template = if tw < 60 {
            if unit == "bytes" {
                format!(
                    "{{spinner:.green}} {} {{bar:.green/red}} {{bytes}}/{{total_bytes}}",
                    effective_msg
                )
            } else {
                format!(
                    "{{spinner:.green}} {} {{bar:.green/red}} {{pos}}/{{len}}",
                    effective_msg
                )
            }
        } else if tw < 80 {
            if unit == "bytes" {
                format!(
                    "{{spinner:.green}} {} {{bar:.green/red}} {{bytes}}/{{total_bytes}} ({{eta}})",
                    effective_msg
                )
            } else {
                format!(
                    "{{spinner:.green}} {} {{bar:.green/red}} {{pos}}/{{len}} [{{percent}}%]",
                    effective_msg
                )
            }
        } else {
            if unit == "bytes" {
                format!("{{spinner:.green}} {} {{wide_bar:.green/red}} {{bytes}} / {{total_bytes}} ({{eta}})", effective_msg)
            } else {
                format!("{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}} ({{eta}}) [{{percent}}%]", effective_msg)
            }
        };

        let style = ProgressStyle::default_bar()
            .template(&template)
            .unwrap_or_else(|_| {
                let ft = if tw < 60 {
                    if unit == "bytes" {
                        format!("{{spinner:.green}} {} {{bar:5.green}} {{bytes}}/{{total_bytes}}", effective_msg)
                    } else {
                        format!("{{spinner:.green}} {} {{bar:5.green}} {{pos}}/{{len}}", effective_msg)
                    }
                } else {
                    if unit == "bytes" {
                        format!("{{spinner:.green}} {} {{bar:5.green}} {{bytes}} / {{total_bytes}} ({{eta}})", effective_msg)
                    } else {
                        format!("{{spinner:.green}} {} {{bar:5.green}} {{pos}}/{{len}} ({{eta}})", effective_msg)
                    }
                };
                ProgressStyle::default_bar().template(&ft).expect("Valid template")
            })
            .tick_strings(&["[|]", "[/]", "[-]", "[\\]"])
            .progress_chars("#>-");

        pb.set_style(style);
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        if let Ok(mut g) = self.progress_bar.lock() {
            *g = Some(pb);
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

    fn paint(&self, icon: &str, msg: &str, color: &str, is_error: bool, is_dim: bool) {
        if self.silent && !is_error {
            return;
        }
        let tw = self.term_width();
        let indent_size = if tw < 40 { 2 } else { icon.len() + 1 };
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
            println!("{}", "License:     MIT".green());
            println!(
                "{}",
                "Description: High-performance cryptographic signer.".magenta()
            );
        } else {
            println!("Author:      {}\nRepository:  https://github.com/MrCarb0n/zipsignerust\nLicense:     MIT\nDescription: High-performance cryptographic signer.", APP_AUTHOR);
        }
    }

    fn supports_color(&self) -> bool {
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
        } else {
            if self.colors {
                eprintln!("{}", header.yellow().bold());
            } else {
                eprintln!("{}", header);
            }
        }
    }

    pub fn info(&self, msg: &str) {
        if self.verbose {
            self.paint("[i]", msg, "34", false, false);
        }
    }
    pub fn verbose(&self, msg: &str) {
        if self.verbose {
            self.paint("[v]", msg, "2", false, true);
        }
    }
    pub fn very_verbose(&self, msg: &str) {
        if self.very_verbose {
            self.paint("[vv]", msg, "2", false, true);
        }
    }
    pub fn debug(&self, msg: &str) {
        if self.debug {
            self.paint("[dbg]", msg, "2", false, true);
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

    pub fn print_summary(&self, title: &str, fields: &[(&str, String)]) {
        if self.silent || !self.verbose {
            return;
        }
        if self.colors {
            eprintln!("{}", format!("{}:", title).green().bold());
        } else {
            eprintln!("{}:", title);
        }
        let tw = self.term_width();

        for (key, val) in fields {
            let base_indent = if tw < 60 { 2 } else { key.len() + 2 };
            let wrapped = self.wrap_msg(val, base_indent);
            let lines: Vec<&str> = wrapped.split('\n').collect();

            for (i, line) in lines.iter().enumerate() {
                if i == 0 {
                    if tw < 60 {
                        if self.colors {
                            eprintln!("{}: {}", key.cyan().bold(), line.green());
                        } else {
                            eprintln!("{}: {}", key, line);
                        }
                    } else {
                        if self.colors {
                            eprintln!("  {:<8} {}", key.cyan().bold(), line.green());
                        } else {
                            eprintln!("  {:<8} {}", key, line);
                        }
                    }
                } else if self.colors {
                    eprintln!("{}{}", " ".repeat(base_indent), line.green());
                } else {
                    eprintln!("{}{}", " ".repeat(base_indent), line);
                }
            }
        }
    }

    fn wrap_msg(&self, msg: &str, indent: usize) -> String {
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
