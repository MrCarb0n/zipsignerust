/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

//! # ZipSigner Rust Library
//!
//! A high-performance, memory-safe library for signing and verifying Android
//! ZIP/JAR archives. It provides the core functionality for the `zipsignerust`
//! command-line tool.

pub mod cli;
pub mod config;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod processor;
pub mod signing;
pub mod ui;
pub mod verification;

pub mod certificate;

pub const APP_NAME: &str = "ZipSignerust";
pub const APP_BIN_NAME: &str = "zipsignerust";
pub const APP_VERSION: &str = "1.0.0";
pub const APP_AUTHOR: &str = "Tiash H Kabir / @MrCarb0n";
pub const APP_ABOUT: &str = "High-performance, memory-safe cryptographic signing and verification for Android ZIP/APK/JAR packages.";
pub const BUFFER_SIZE: usize = 64 * 1024;

pub const MANIFEST_NAME: &str = "META-INF/MANIFEST.MF";
pub const CERT_SF_NAME: &str = "META-INF/CERT.SF";
pub const CERT_RSA_NAME: &str = "META-INF/CERT.RSA";

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
