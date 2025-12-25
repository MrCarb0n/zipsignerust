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

//! Core library for ZipSigner Rust - provides signing and verification functionality for Android ZIP archives.

pub mod cli;
pub mod config;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod pkcs7;
pub mod processor;
pub mod signing;
pub mod ui;
pub mod verification;

pub mod certificate;

pub const APP_NAME: &str = "ZipSignerust";
pub const APP_BIN_NAME: &str = "zipsignerust";
pub const APP_VERSION: &str = "1.0.0";
pub const APP_AUTHOR: &str = "Tiash H Kabir / @MrCarb0n";
pub const APP_ABOUT: &str = "High-performance, memory-safe cryptographic signing and verification for Android ZIP archives.";
pub const BUFFER_SIZE: usize = 64 * 1024;

pub const MANIFEST_NAME: &str = "META-INF/MANIFEST.MF";
pub const CERT_SF_NAME: &str = "META-INF/CERT.SF";
pub const CERT_RSA_NAME: &str = "META-INF/CERT.RSA";
pub const CERT_PUBLIC_KEY_NAME: &str = "META-INF/CERT.DSA"; // Android expects certificate file (DSA, EC, or RSA)

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
