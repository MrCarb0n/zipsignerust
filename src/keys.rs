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

use crate::{error::SignerError, ui::Ui};
use ::pem as pem_crate;
use ring::signature::{self, RsaKeyPair, UnparsedPublicKey};
use std::{fs, path::Path};
use x509_parser::prelude::*;
use zip::DateTime;

pub const RSA_SIGNATURE_SCHEME: &dyn signature::RsaEncoding = &signature::RSA_PKCS1_SHA256;

pub const RSA_VERIFICATION_ALGORITHM: &'static dyn signature::VerificationAlgorithm =
    &signature::RSA_PKCS1_2048_8192_SHA256;

pub struct KeyChain {
    pub private_key: Option<RsaKeyPair>,
    pub public_key: Option<UnparsedPublicKey<Vec<u8>>>,
    pub cert_not_before: Option<DateTime>,
    pub cert_der: Option<Vec<u8>>, // DER encoded certificate data
}

type LoadedPublicKey = (
    Option<UnparsedPublicKey<Vec<u8>>>,
    Option<DateTime>,
    Option<Vec<u8>>,
);

impl KeyChain {
    /// Load signing keys from files or use defaults
    pub fn new(
        priv_path: Option<&Path>,
        pub_path: Option<&Path>,
        ui: &Ui,
    ) -> Result<Self, SignerError> {
        let private_key = Self::load_private_key(priv_path, ui)?;
        let (public_key, cert_not_before, cert_der) = Self::load_public_key(pub_path, ui)?;

        if private_key.is_none() && public_key.is_none() {
            return Err(SignerError::Config(
                "Failed to load any keys (both custom and default failed).".into(),
            ));
        }

        Ok(Self {
            private_key,
            public_key,
            cert_not_before,
            cert_der,
        })
    }

    fn load_private_key(path: Option<&Path>, ui: &Ui) -> Result<Option<RsaKeyPair>, SignerError> {
        let content = match path {
            Some(p) => {
                Self::check_key_permissions(p, ui)?;
                fs::read(p)?
            }
            None => {
                ui.warn("Using dev key. For production: -k flag.");
                crate::certificate::PRIVATE_KEY.as_bytes().to_vec()
            }
        };

        let key_pair = match pem_crate::parse(&content) {
            Ok(pem) => RsaKeyPair::from_pkcs8(pem.contents())
                .map_err(|e| SignerError::Config(format!("Invalid PEM private key: {}", e)))?,
            Err(_) => {
                ui.debug("Input is not PEM, attempting to parse as binary PK8/DER...");
                RsaKeyPair::from_pkcs8(&content).map_err(|e| {
                    SignerError::Config(format!("Invalid private key format: {}", e))
                })?
            }
        };

        Ok(Some(key_pair))
    }

    fn load_public_key(path: Option<&Path>, ui: &Ui) -> Result<LoadedPublicKey, SignerError> {
        let content = match path {
            Some(p) => fs::read(p)?,
            None => {
                ui.warn("Using dev cert. For production: -p flag.");
                crate::certificate::PUBLIC_KEY.as_bytes().to_vec()
            }
        };

        let cert_der = match pem_crate::parse(&content) {
            Ok(pem) => pem.contents().to_vec(),
            Err(_) => {
                ui.debug("Input is not PEM, attempting to parse as binary X.509 DER...");
                content
            }
        };

        let (_, cert) = X509Certificate::from_der(&cert_der)
            .map_err(|e| SignerError::Config(format!("Invalid certificate: {}", e)))?;

        let pk_der = cert.public_key().subject_public_key.data.to_vec();
        let nb = Some(Self::asn1_to_zip_datetime(cert.validity().not_before, ui));

        Ok((
            Some(UnparsedPublicKey::new(RSA_VERIFICATION_ALGORITHM, pk_der)),
            nb,
            Some(cert_der),
        ))
    }

    pub fn get_reproducible_timestamp(&self) -> DateTime {
        if let Some(dt) = &self.cert_not_before {
            return *dt;
        }
        // Fallback only if absolutely no certificate date is found.
        DateTime::from_date_and_time(2008, 1, 1, 0, 0, 0).unwrap_or_else(|_| {
            DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap()
        })
    }

    #[cfg(unix)]
    fn check_key_permissions(path: &Path, ui: &Ui) -> Result<(), SignerError> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let permissions = metadata.permissions().mode();
        if permissions & 0o077 != 0 {
            ui.warn(&format!(
                "Private key '{}' is accessible by others (mode {:o}).",
                path.display(),
                permissions
            ));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_key_permissions(_path: &Path, _ui: &Ui) -> Result<(), SignerError> {
        Ok(())
    }

    fn asn1_to_zip_datetime(asn1: ASN1Time, ui: &Ui) -> DateTime {
        let dt = asn1.to_datetime();

        let year = (dt.year() as u16).clamp(1980, 2107);

        let month = dt.month() as u8;
        let day = dt.day();
        let hour = dt.hour();
        let minute = dt.minute();
        let second = dt.second();

        DateTime::from_date_and_time(year, month, day, hour, minute, second).unwrap_or_else(|_| {
            ui.error("Failed to create DateTime from certificate. Fallback used.");
            DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).unwrap_or_else(|_| {
                // If both fail, use a basic fallback that should always work
                DateTime::default()
            })
        })
    }
}
