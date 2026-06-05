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
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

/// Manifest field names that must not be wrapped per JAR spec.
pub mod fields {
    pub const NAME: &str = "Name";
    pub const SHA1_DIGEST: &str = "SHA1-Digest";
    pub const SHA256_DIGEST: &str = "SHA-256-Digest";
    pub const SHA1_DIGEST_MANIFEST: &str = "SHA1-Digest-Manifest";
    pub const SHA256_DIGEST_MANIFEST: &str = "SHA-256-Digest-Manifest";
    pub const MD5_DIGEST_MANIFEST: &str = "MD5-Digest-Manifest";
}

/// One labeled value row in `Ui::print_summary`. Replaces the prior
/// `&[(&str, String)]` borrow slice so the call site is type-checked and
/// the label set can be enumerated.
#[derive(Debug, Clone)]
pub struct SummaryField {
    pub label: &'static str,
    pub value: String,
}

impl SummaryField {
    pub fn new(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
        }
    }
}

struct UiInner {
    progress_bar: Option<ProgressBar>,
    is_bytes_progress: bool,
    temp_files: Vec<std::path::PathBuf>,
}

pub struct Ui {
    pub verbose: bool,
    pub very_verbose: bool,
    pub debug: bool,
    silent: bool,
    colors: bool,
    inner: Arc<Mutex<UiInner>>,
    cached_width: RefCell<Option<usize>>,
}

impl Default for Ui {
    fn default() -> Self {
        Self::silent()
    }
}

impl Ui {
    /// All output suppressed, no colors. Use in tests and quiet mode.
    pub fn silent() -> Self {
        Self::new(false, false, false, true, false)
    }

    /// Bare constructor. Prefer `silent()` for tests; prefer
    /// `from_verbosity_level` for runtime use.
    pub fn new(v: bool, vv: bool, d: bool, s: bool, c: bool) -> Self {
        Self {
            verbose: v,
            very_verbose: vv,
            debug: d,
            silent: s,
            colors: c,
            inner: Arc::new(Mutex::new(UiInner {
                progress_bar: None,
                is_bytes_progress: false,
                temp_files: Vec::new(),
            })),
            cached_width: RefCell::new(None),
        }
    }

    pub fn from_verbosity_level(level: u8, s: bool, c: bool) -> Self {
        Self::new(level >= 1, level >= 2, level >= 3, s, c)
    }

    /// Build a ProgressStyle from a template with a single fallback chain.
    ///
    /// Tries the primary template, falls back to a simple bar without
    /// color/eta on parse error, and finally to a minimal default if that
    /// also fails. Never panics.
    fn build_progress_style(primary: &str, fallback: &str) -> ProgressStyle {
        ProgressStyle::default_bar()
            .template(primary)
            .unwrap_or_else(|_| {
                ProgressStyle::default_bar()
                    .template(fallback)
                    .unwrap_or_else(|_| ProgressStyle::default_bar())
            })
    }

    pub fn show_progress_bar(&self, len: u64, msg: &str) {
        let pb = ProgressBar::new(len);
        let tw = self.term_width();
        let effective_msg = Self::truncate_msg(msg, tw);

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

        let fallback = format!(
            "{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}}",
            effective_msg
        );

        let style = Self::build_progress_style(&template, &fallback)
            .tick_strings(&["[|]", "[/]", "[-]", "[\\]"])
            .progress_chars("#>-");

        pb.set_style(style);
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        if let Ok(mut inner) = self.inner.lock() {
            inner.progress_bar = Some(pb);
        }
    }

    pub fn record_temp_file(&self, path: &std::path::Path) {
        if self.debug {
            if let Ok(mut inner) = self.inner.lock() {
                inner.temp_files.push(path.to_path_buf());
                self.debug(&format!("Recorded: {:?}", path));
            }
        }
    }

    pub fn print_temp_files(&self) {
        if self.debug {
            if let Ok(inner) = self.inner.lock() {
                if !inner.temp_files.is_empty() {
                    self.info(&format!("Files: {} item(s)", inner.temp_files.len()));
                    for path in inner.temp_files.iter() {
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
            format!("{}{}", bytes, UNITS[unit_idx])
        } else if size.fract() < 0.01 {
            format!("{:.0}{}", size, UNITS[unit_idx])
        } else {
            format!("{:.1}{}", size, UNITS[unit_idx])
        }
    }

    pub fn show_detailed_progress_bar(&self, len: u64, msg: &str, unit: &str) {
        let pb = ProgressBar::new(len);
        let tw = self.term_width();
        let effective_msg = Self::truncate_msg(msg, tw);

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
            format!(
                "{{spinner:.green}} {} {{wide_bar:.green/red}} ({{msg}}) ({{eta}})",
                effective_msg
            )
        } else {
            format!("{{spinner:.green}} {} {{wide_bar:.green/red}} {{pos}}/{{len}} ({{eta}}) [{{percent}}%]", effective_msg)
        };

        let fallback = if tw < 60 {
            if unit == "bytes" {
                format!(
                    "{{spinner:.green}} {} {{wide_bar:.green}} ({{msg}})",
                    effective_msg
                )
            } else {
                format!(
                    "{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}}",
                    effective_msg
                )
            }
        } else if unit == "bytes" {
            format!(
                "{{spinner:.green}} {} {{wide_bar:.green}} ({{msg}}) ({{eta}})",
                effective_msg
            )
        } else {
            format!(
                "{{spinner:.green}} {} {{wide_bar:.green}} {{pos}}/{{len}} ({{eta}})",
                effective_msg
            )
        };

        let style = Self::build_progress_style(&template, &fallback)
            .tick_strings(&["[|]", "[/]", "[-]", "[\\]"])
            .progress_chars("#>-");

        pb.set_style(style);
        pb.enable_steady_tick(std::time::Duration::from_millis(120));

        if unit == "bytes" {
            pb.set_message(Self::format_bytes(pb.position()));
        }

        if let Ok(mut inner) = self.inner.lock() {
            inner.is_bytes_progress = unit == "bytes";
            inner.progress_bar = Some(pb);
        }
    }

    pub fn update_progress(&self, pos: u64) {
        let _ = self.inner.lock().map(|inner| {
            if let Some(ref pb) = inner.progress_bar {
                pb.set_position(pos);

                if inner.is_bytes_progress {
                    let total = pb.length().unwrap_or(0);
                    pb.set_message(format!(
                        "{} / {}",
                        Self::format_bytes(pos),
                        Self::format_bytes(total)
                    ));
                }
            }
        });
    }

    pub fn finish_progress(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(ref pb) = inner.progress_bar {
                if inner.is_bytes_progress {
                    let total = pb.length().unwrap_or(0);
                    pb.set_message(format!(
                        "{} / {}",
                        Self::format_bytes(total),
                        Self::format_bytes(total)
                    ));
                }
                pb.finish_and_clear();
            }
            inner.progress_bar = None;
        }
    }

    pub fn has_progress_bar(&self) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.progress_bar.is_some())
            .unwrap_or(false)
    }

    /// Build the per-line `Option<ColoredString>` for an icon + line, or
    /// `None` when colors are disabled (let the caller fall through to the
    /// plain-text branch with a single icon string).
    fn colorize<'a>(
        &self,
        icon: &'a str,
        line: &'a str,
        color: &str,
        is_dim: bool,
    ) -> Option<(ColoredString, ColoredString)> {
        if !self.supports_color() {
            return None;
        }
        let ic = match color {
            "31" => icon.red().bold(),
            "32" => icon.green().bold(),
            "33" => icon.yellow().bold(),
            "34" => icon.blue().bold(),
            "36" => icon.cyan().bold(),
            _ => icon.bold(),
        };
        let ln = if is_dim { line.dimmed() } else { line.normal() };
        Some((ic, ln))
    }

    fn paint(&self, icon: &str, msg: &str, color: &str, is_error: bool, is_dim: bool) {
        if self.silent && !is_error {
            return;
        }
        const INDENT: &str = "    ";
        let wrapped = self.wrap_msg(msg, INDENT.len());
        let lines: Vec<&str> = wrapped.split('\n').collect();

        for (i, line) in lines.iter().enumerate() {
            match self.colorize(icon, line, color, is_dim) {
                Some((ic, ln)) if i == 0 => eprintln!("{} {}", ic, ln),
                Some((_, ln)) => eprintln!("{}{}", INDENT, ln),
                None if i == 0 => eprintln!("{} {}", icon, line),
                None => eprintln!("{}{}", INDENT, line),
            }
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
            if self.supports_color() {
                eprintln!("{}", title.cyan().bold());
            } else {
                eprintln!("{}", title);
            }
        } else {
            let border = "-".repeat(width);
            if self.supports_color() {
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
        if self.supports_color() {
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

    /// Windows consoles do not auto-detect TTY for ANSI; force-enable when
    /// the user did not pass `--no-color`. On non-Windows this is a no-op
    /// because the `colored` crate probes the TTY itself.
    pub fn force_color_on_windows(&mut self) {
        #[cfg(windows)]
        if self.colors {
            colored::control::set_override(true);
        }
        let _ = self;
    }

    pub fn print_mode_header(&self, title: &str) {
        if self.silent || !self.verbose {
            return;
        }
        eprintln!();
        let header = format!("-- {} --", title);
        let tw = self.term_width();
        if tw < header.len() {
            if self.supports_color() {
                eprintln!("{}", title.yellow().bold());
            } else {
                eprintln!("{}", title);
            }
        } else if self.supports_color() {
            eprintln!("{}", header.yellow().bold());
        } else {
            eprintln!("{}", header);
        }
    }

    pub fn info(&self, msg: &str) {
        if self.verbose {
            self.paint("[i]", msg, "34", false, false);
        }
    }
    pub fn debug(&self, msg: &str) {
        if self.very_verbose {
            self.paint("[d]", msg, "2", false, true);
        }
    }
    pub fn trace(&self, msg: &str) {
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

    pub fn print_section_header(&self, title: &str) {
        if self.supports_color() {
            eprintln!("{}", format!("{}:", title).green().bold());
        } else {
            eprintln!("{}:", title);
        }
    }

    pub fn print_help_item(&self, command: &str, description: &str) {
        const COLUMN_WIDTH: usize = 18;
        let padded_command = format!("  {:<width$}", command, width = COLUMN_WIDTH - 2);
        let wrapped_description = self.wrap_msg(description, COLUMN_WIDTH);
        let lines: Vec<&str> = wrapped_description.split('\n').collect();

        for (i, line) in lines.iter().enumerate() {
            if i == 0 {
                if self.supports_color() {
                    eprintln!("{}{}", padded_command, line.normal());
                } else {
                    eprintln!("{}{}", padded_command, line);
                }
            } else {
                let indent = " ".repeat(COLUMN_WIDTH);
                if self.supports_color() {
                    eprintln!("{}{}", indent, line.normal());
                } else {
                    eprintln!("{}{}", indent, line);
                }
            }
        }
    }

    pub fn print_help_section(&self, title: &str, items: &[(&str, &str)]) {
        self.print_section_header(title);
        for (command, description) in items {
            self.print_help_item(command, description);
        }
        eprintln!();
    }

    pub fn print_summary(&self, title: &str, fields: &[SummaryField]) {
        if self.silent || !self.verbose {
            return;
        }
        if self.supports_color() {
            eprintln!("{}", format!("{}:", title).green().bold());
        } else {
            eprintln!("{}:", title);
        }

        const BASE_INDENT: usize = 4;
        for SummaryField { label, value } in fields {
            let wrapped = self.wrap_msg(value, BASE_INDENT);
            let lines: Vec<&str> = wrapped.split('\n').collect();

            for (i, line) in lines.iter().enumerate() {
                if i == 0 {
                    if self.supports_color() {
                        eprintln!("    {}: {}", label.cyan().bold(), line.green());
                    } else {
                        eprintln!("    {}: {}", label, line);
                    }
                } else if self.supports_color() {
                    eprintln!("{}{}", " ".repeat(BASE_INDENT), line.green());
                } else {
                    eprintln!("{}{}", " ".repeat(BASE_INDENT), line);
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

    pub(crate) fn term_width(&self) -> usize {
        if let Some(w) = *self.cached_width.borrow() {
            return w;
        }
        let w = std::env::var("COLUMNS")
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
            .unwrap_or(80);
        *self.cached_width.borrow_mut() = Some(w);
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(Ui::format_bytes(0), "0B");
    }

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(Ui::format_bytes(500), "500B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(Ui::format_bytes(1024), "1KB");
        assert_eq!(Ui::format_bytes(1536), "1.5KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(Ui::format_bytes(1048576), "1MB");
        assert_eq!(Ui::format_bytes(2097152), "2MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(Ui::format_bytes(1073741824), "1GB");
    }

    #[test]
    fn test_truncate_msg_short() {
        assert_eq!(Ui::truncate_msg("hello", 100), "hello");
    }

    #[test]
    fn test_truncate_msg_wide_terminal() {
        let msg = "hello world this is long";
        assert_eq!(Ui::truncate_msg(msg, 100), msg);
    }

    #[test]
    fn test_truncate_msg_very_narrow() {
        let msg = "hello world this is very long message";
        let result = Ui::truncate_msg(msg, 30);
        assert_eq!(result, "hello wo...");
    }

    #[test]
    fn test_silent_factory() {
        let ui = Ui::silent();
        assert!(!ui.verbose);
        assert!(!ui.very_verbose);
        assert!(!ui.debug);
        assert!(ui.silent);
        assert!(!ui.colors);
    }

    #[test]
    fn test_from_verbosity_level() {
        let ui = Ui::from_verbosity_level(1, false, true);
        assert!(ui.verbose);
        assert!(!ui.very_verbose);
        assert!(!ui.debug);

        let ui = Ui::from_verbosity_level(2, false, true);
        assert!(ui.verbose);
        assert!(ui.very_verbose);
        assert!(!ui.debug);

        let ui = Ui::from_verbosity_level(3, false, true);
        assert!(ui.verbose);
        assert!(ui.very_verbose);
        assert!(ui.debug);
    }

    #[test]
    fn test_wrap_msg_short_text() {
        std::env::set_var("COLUMNS", "80");
        let ui = Ui::silent();
        assert_eq!(ui.wrap_msg("hello world", 4), "hello world");
    }

    #[test]
    fn test_wrap_msg_respects_width() {
        std::env::set_var("COLUMNS", "20");
        let ui = Ui::silent();
        let out = ui.wrap_msg("the quick brown fox jumps over the lazy dog", 0);
        for line in out.split('\n') {
            assert!(line.chars().count() <= 20, "line too wide: {}", line);
        }
    }

    #[test]
    fn test_wrap_msg_chunks_long_word() {
        std::env::set_var("COLUMNS", "10");
        let ui = Ui::silent();
        let out = ui.wrap_msg("supercalifragilisticexpialidocious", 0);
        for line in out.split('\n') {
            assert!(line.chars().count() <= 10, "line too wide: {}", line);
        }
    }

    #[test]
    fn test_summary_field_construction() {
        let f = SummaryField::new("Status", "Success");
        assert_eq!(f.label, "Status");
        assert_eq!(f.value, "Success");
    }
}
