/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2024 Tiash / @MrCarb0n and Earth Inc.
 * Licensed under the MIT License.
 */

use crate::{error::SignerError, APP_NAME, APP_VERSION};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
}

// Simplified output: text only

static VERBOSE: AtomicBool = AtomicBool::new(false);
static SILENT: AtomicBool = AtomicBool::new(false);
static COLORS: AtomicBool = AtomicBool::new(true);

// Minimal mode: no timestamp/pid

fn enabled(_l: LogLevel, is_error: bool, essential: bool) -> bool {
    if SILENT.load(Ordering::Relaxed) {
        return false;
    }
    if is_error {
        return true;
    }
    if VERBOSE.load(Ordering::Relaxed) {
        return true;
    }
    essential
}

// Audit disabled

fn ascii_icon(level: &str) -> &'static str {
    match level {
        "INFO" => "[i]",
        "OK" => "[v]",
        "WARN" => "[!]",
        "ERROR" => "[X]",
        "DETAIL" => "[>]",
        _ => "[.]",
    }
}

fn paint(level: &str, msg: &str, color: &str, is_error: bool) {
    let icon = ascii_icon(level);
    let icon_render = if COLORS.load(Ordering::Relaxed) {
        format!("\x1b[{}m{}\x1b[0m", color, icon)
    } else {
        icon.to_string()
    };
    let line = format!("{} {}", icon_render, msg);
    if is_error {
        eprintln!("{}", line);
    } else {
        println!("{}", line);
    }
}

pub fn print_banner() {
    if SILENT.load(Ordering::Relaxed) || !VERBOSE.load(Ordering::Relaxed) {
        return;
    }
    let title = format!("{} v{}", APP_NAME, APP_VERSION);
    let width = title.len() + 4;
    let top = format!("+{}+", "-".repeat(width));
    let mid = format!("|  {}  |", title);
    let bot = top.clone();
    println!("{}", top);
    println!("{}", mid);
    println!("{}", bot);
}

pub fn print_mode_header(title: &str) {
    if SILENT.load(Ordering::Relaxed) || !VERBOSE.load(Ordering::Relaxed) {
        return;
    }
    let line = format!("-- {} --", title);
    println!("{}", line);
}

pub fn log_info(msg: &str) {
    if enabled(LogLevel::Info, false, false) {
        paint("INFO", msg, "34", false);
    }
}

pub fn log_success(msg: &str) {
    if enabled(LogLevel::Info, false, true) {
        paint("OK", msg, "32", false);
    }
}

pub fn log_warn(msg: &str) {
    if enabled(LogLevel::Warn, false, false) {
        paint("WARN", msg, "33", false);
    }
}

pub fn log_error(msg: &str) {
    if enabled(LogLevel::Error, true, false) {
        paint("ERROR", msg, "31", true);
    }
}

pub fn log_error_detail(msg: &str) {
    if enabled(LogLevel::Error, true, false) {
        paint("DETAIL", msg, "31", true);
    }
}

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

pub fn set_silent(s: bool) {
    SILENT.store(s, Ordering::Relaxed);
}
pub fn is_silent() -> bool {
    SILENT.load(Ordering::Relaxed)
}
pub fn set_colors(c: bool) {
    COLORS.store(c, Ordering::Relaxed);
}

pub fn log_structured_error(err: &SignerError) {
    paint("ERROR", &err.to_string(), "31", true);
}
