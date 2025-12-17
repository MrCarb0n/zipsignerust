/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

use crate::{error::SignerError, ui::Ui, BUFFER_SIZE};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use ring::digest;
use std::io::Read;

pub struct CryptoEngine;

impl CryptoEngine {
    pub fn compute_sha1(data: &[u8]) -> String {
        base64_engine.encode(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref())
    }

    pub fn compute_sha1_with_ui(data: &[u8], ui: Option<&Ui>) -> String {
        if let Some(ui) = ui {
            if ui.debug {
                ui.debug(&format!("SHA1: {} bytes", data.len()));
            }
        }
        Self::compute_sha1(data)
    }

    pub fn compute_stream_sha1<R: Read>(reader: &mut R) -> Result<String, SignerError> {
        Self::compute_stream_sha1_with_ui(reader, None, None)
    }

    pub fn compute_stream_sha1_with_ui<R: Read>(
        reader: &mut R,
        ui: Option<&Ui>,
        file_path: Option<&str>,
    ) -> Result<String, SignerError> {
        let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);

        if let Some(ui) = ui {
            if let Some(path) = file_path {
                let msg = format!("SHA1: {}", path);
                if ui.very_verbose {
                    ui.very_verbose(&msg);
                } else if ui.verbose {
                    ui.verbose(&msg);
                }
            }
        }

        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut processed = 0u64;
        loop {
            let count = reader.read(&mut buf)?;
            if count == 0 {
                break;
            }
            ctx.update(&buf[..count]);
            processed += count as u64;

            if let Some(ui) = ui {
                if ui.debug && processed % (BUFFER_SIZE as u64 * 10) == 0 {
                    ui.debug(&format!("SHA1: {} bytes", processed));
                }
            }
        }

        if let Some(ui) = ui {
            if ui.very_verbose {
                ui.very_verbose(&format!("SHA1 complete: {} bytes", processed));
            }
        }

        Ok(base64_engine.encode(ctx.finish().as_ref()))
    }
}
