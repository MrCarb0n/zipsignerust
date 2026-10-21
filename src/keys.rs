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
use ring::signature::{self, RsaKeyPair, UnparsedPublicKey};
use std::{fs, path::Path};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::{ASN1Time, FromDer};
use zip::DateTime;

pub const RSA_SIGNATURE_SCHEME: &dyn signature::RsaEncoding = &signature::RSA_PKCS1_SHA256;

pub const RSA_VERIFICATION_ALGORITHM: &dyn signature::VerificationAlgorithm =
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
        let chain = Self {
            private_key,
            public_key,
            cert_not_before,
            cert_der,
        };
        chain.check_matching_pair()?;
        Ok(chain)
    }

    /// Load only the certificate/public key, for verification
    pub fn for_verification(pub_path: Option<&Path>, ui: &Ui) -> Result<Self, SignerError> {
        let (public_key, cert_not_before, cert_der) = Self::load_public_key(pub_path, ui)?;
        Ok(Self {
            private_key: None,
            public_key,
            cert_not_before,
            cert_der,
        })
    }

    /// Sign a probe message and verify it with the certificate key, so a
    /// custom key/cert pair that does not match is rejected instead of
    /// silently producing an archive no verifier accepts.
    fn check_matching_pair(&self) -> Result<(), SignerError> {
        let (Some(private), Some(public)) = (&self.private_key, &self.public_key) else {
            return Ok(());
        };
        let msg = b"zipsignerust key pair self-test";
        let mut signature = vec![0u8; private.public().modulus_len()];
        private
            .sign(
                RSA_SIGNATURE_SCHEME,
                &ring::rand::SystemRandom::new(),
                msg,
                &mut signature,
            )
            .map_err(|e| SignerError::Config(format!("Key pair self-test failed: {}", e)))?;
        public.verify(msg, &signature).map_err(|_| {
            SignerError::Config(
                "Private key does not match the certificate. Pass a matching \
                 --private-key/--public-key pair, or neither to use the embedded dev key."
                    .into(),
            )
        })
    }

    fn load_private_key(path: Option<&Path>, ui: &Ui) -> Result<Option<RsaKeyPair>, SignerError> {
        let content = match path {
            Some(p) => {
                Self::check_key_permissions(p, ui)?;
                fs::read(p)?
            }
            None => {
                let tw = ui.term_width();
                let ruler = "=".repeat(tw.min(50));
                ui.warn(&ruler);
                ui.warn("  EMBEDDED DEV KEY IN USE");
                ui.warn("  Output is NOT authentic. Supply --private-key for production.");
                ui.warn(&ruler);
                crate::certificate::PRIVATE_KEY.as_bytes().to_vec()
            }
        };

        let key_pair = match ::pem::parse(&content) {
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
                ui.warn("Using embedded dev certificate.");
                crate::certificate::PUBLIC_KEY.as_bytes().to_vec()
            }
        };

        let cert_der = match ::pem::parse(&content) {
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
        // Chain two fixed dates then DateTime::default() so we never panic.
        DateTime::from_date_and_time(2008, 1, 1, 0, 0, 0).unwrap_or_else(|_| {
            DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0)
                .unwrap_or_else(|_| DateTime::default())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dev_key_pair_passes_matching_check() {
        let keys = KeyChain::new(None, None, &Ui::silent()).unwrap();
        assert!(keys.check_matching_pair().is_ok());
    }

    #[test]
    fn test_mismatched_public_key_is_rejected() {
        let ui = Ui::silent();
        let keys = KeyChain::new(None, None, &ui).unwrap();

        // One flipped bit in the public key is enough for the probe signature to fail.
        let mut modulus = keys.public_key.as_ref().unwrap().as_ref().to_vec();
        let mid = modulus.len() / 2;
        modulus[mid] ^= 1;

        let wrong = KeyChain {
            private_key: keys.private_key,
            public_key: Some(UnparsedPublicKey::new(RSA_VERIFICATION_ALGORITHM, modulus)),
            cert_not_before: keys.cert_not_before,
            cert_der: keys.cert_der,
        };
        let err = match wrong.check_matching_pair() {
            Err(e) => e,
            Ok(()) => panic!("mismatched public key must be rejected"),
        };
        assert!(
            err.to_string().contains("does not match"),
            "unexpected error: {}",
            err
        );
    }
}
