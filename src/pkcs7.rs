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

use crate::{error::SignerError, keys::KeyChain};
use simple_asn1::{from_der, ASN1Block, BigInt, OID};
use x509_parser::prelude::*;

fn encode_len(sz: usize) -> Vec<u8> {
    if sz < 128 {
        vec![sz as u8]
    } else {
        let mut parts = Vec::new();
        let mut n = sz;
        while n > 0 {
            parts.push((n & 0xFF) as u8);
            n >>= 8;
        }
        parts.reverse();
        let mut res = vec![0x80 | (parts.len() as u8)];
        res.extend(parts);
        res
    }
}

fn wrap_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut res = vec![tag];
    res.extend(encode_len(content.len()));
    res.extend_from_slice(content);
    res
}

fn seq_items<'b>(block: &'b ASN1Block, what: &str) -> Result<&'b [ASN1Block], SignerError> {
    match block {
        ASN1Block::Sequence(_, v) | ASN1Block::Set(_, v) => Ok(v),
        _ => Err(SignerError::Validation(format!(
            "Expected SEQUENCE/SET for {}",
            what
        ))),
    }
}

/// Attribute items plus the re-tagged `SET OF` encoding the signature covers.
/// The `[0]` slot holds raw SET content (Unknown) for 2+ attributes, or a
/// single Attribute (Explicit) — both fold to the same pair.
fn attrs_set(slot: &ASN1Block) -> Result<(Vec<ASN1Block>, Vec<u8>), SignerError> {
    let asn1_err = |e| SignerError::Validation(format!("PKCS7 parse error: {}", e));
    match slot {
        ASN1Block::Unknown(_, _, _, _, bytes) => {
            let items = from_der(bytes).map_err(asn1_err)?;
            Ok((items, wrap_tag(0x31, bytes)))
        }
        ASN1Block::Explicit(_, _, _, inner) => {
            let inner_der = simple_asn1::to_der(inner)
                .map_err(|e| SignerError::Validation(format!("PKCS7 encode error: {}", e)))?;
            Ok((vec![(**inner).clone()], wrap_tag(0x31, &inner_der)))
        }
        _ => Err(SignerError::Validation(
            "Authenticated attributes not found".into(),
        )),
    }
}

/// messageDigest bytes from a single Attribute, if its OID matches.
fn attr_digest(attr: &ASN1Block, md_oid: &OID) -> Option<Vec<u8>> {
    match attr {
        ASN1Block::Sequence(_, items) => match items.as_slice() {
            [ASN1Block::ObjectIdentifier(_, o), ASN1Block::Set(_, vals)] if o == md_oid => {
                match vals.as_slice() {
                    [ASN1Block::OctetString(_, d)] => Some(d.clone()),
                    _ => None,
                }
            }
            _ => None,
        },
        _ => None,
    }
}

/// PKCS7 signer info extracted from a signature blob.
pub struct SignerInfo {
    pub signature: Vec<u8>,
    pub auth_attrs_der: Vec<u8>,
    pub message_digest: Vec<u8>,
}

/// Extract PKCS7 signer info: signature_bytes, auth_attrs_der_with_set_tag, expected_sf_digest
pub fn extract_signer_info(pkcs7_der: &[u8]) -> Result<SignerInfo, SignerError> {
    let asn1_err = |e| SignerError::Validation(format!("PKCS7 parse error: {}", e));
    let top = from_der(pkcs7_der).map_err(asn1_err)?;
    let ci = seq_items(
        top.first()
            .ok_or_else(|| SignerError::Validation("Empty PKCS7".into()))?,
        "ContentInfo",
    )?;
    // ContentInfo = SEQUENCE { OID, [0] EXPLICIT SignedData }.
    let sd_seq = match ci.iter().find(|b| matches!(b, ASN1Block::Explicit(..))) {
        Some(ASN1Block::Explicit(_, _, _, inner)) => seq_items(inner.as_ref(), "SignedData")?,
        _ => return Err(SignerError::Validation("SignedData not found".into())),
    };
    // SignedData holds two SETs (digestAlgorithms, signerInfos): want the last.
    let si_items = sd_seq
        .iter()
        .filter_map(|b| match b {
            ASN1Block::Set(_, v) => Some(v.as_slice()),
            _ => None,
        })
        .last()
        .ok_or_else(|| SignerError::Validation("SignerInfos not found".into()))?;
    let si = seq_items(
        si_items
            .first()
            .ok_or_else(|| SignerError::Validation("Empty SignerInfos".into()))?,
        "SignerInfo",
    )?;
    // Authenticated attributes live in the [0] slot.
    let attrs_slot = si
        .iter()
        .find(|b| matches!(b, ASN1Block::Explicit(..) | ASN1Block::Unknown(..)))
        .ok_or_else(|| SignerError::Validation("Authenticated attributes not found".into()))?;
    let (attr_items, auth_attrs_der) = attrs_set(attrs_slot)?;
    let signature = si
        .iter()
        .find_map(|b| match b {
            ASN1Block::OctetString(_, sig) => Some(sig.clone()),
            _ => None,
        })
        .ok_or_else(|| SignerError::Validation("Signature not found".into()))?;
    let md_oid = simple_asn1::oid!(1, 2, 840, 113549, 1, 9, 4);
    let digest = attr_items
        .iter()
        .find_map(|a| attr_digest(a, &md_oid))
        .ok_or_else(|| {
            SignerError::Validation("messageDigest not found in authenticated attributes".into())
        })?;
    Ok(SignerInfo {
        signature,
        auth_attrs_der,
        message_digest: digest,
    })
}

pub fn gen_rsa(keys: &KeyChain, sf: &[u8]) -> Result<Vec<u8>, SignerError> {
    use ring::{digest, signature};

    let key_pair = keys
        .private_key
        .as_ref()
        .ok_or_else(|| SignerError::Config("Private key missing for signing".into()))?;

    let cert_der = keys
        .cert_der
        .as_ref()
        .ok_or_else(|| SignerError::Config("Certificate missing for signing".into()))?;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| SignerError::Config(format!("Failed to parse cert for PKCS7: {}", e)))?;

    let issuer_der = cert.tbs_certificate.issuer.as_raw();
    let serial_bytes = cert.tbs_certificate.serial.to_bytes_be();
    let serial_bigint = BigInt::from_signed_bytes_be(&serial_bytes);

    let oid_data = simple_asn1::oid!(1, 2, 840, 113549, 1, 7, 1);
    let oid_signed_data = simple_asn1::oid!(1, 2, 840, 113549, 1, 7, 2);
    let oid_sha256 = simple_asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
    let oid_rsa = simple_asn1::oid!(1, 2, 840, 113549, 1, 1, 1);
    let oid_content_type = simple_asn1::oid!(1, 2, 840, 113549, 1, 9, 3);
    let oid_message_digest = simple_asn1::oid!(1, 2, 840, 113549, 1, 9, 4);

    let attr_ct = ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::ObjectIdentifier(0, oid_content_type),
            ASN1Block::Set(0, vec![ASN1Block::ObjectIdentifier(0, oid_data.clone())]),
        ],
    );

    let digest_sha256 = digest::digest(&digest::SHA256, sf);
    let digest_bytes = digest_sha256.as_ref().to_vec();

    let attr_md = ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::ObjectIdentifier(0, oid_message_digest),
            ASN1Block::Set(0, vec![ASN1Block::OctetString(0, digest_bytes)]),
        ],
    );

    let auth_attrs_set = ASN1Block::Set(0, vec![attr_ct, attr_md]);
    let auth_attrs_der = simple_asn1::to_der(&auth_attrs_set)
        .map_err(|e| SignerError::Config(format!("ASN1 encode error: {}", e)))?;

    let mut auth_attrs_implicit = auth_attrs_der.clone();
    if auth_attrs_implicit.is_empty() || auth_attrs_implicit[0] != 0x31 {
        return Err(SignerError::Config(
            "Failed to generate attributes SET".into(),
        ));
    }
    auth_attrs_implicit[0] = 0xA0;

    let mut signature_bytes = vec![0u8; key_pair.public().modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    key_pair.sign(
        &signature::RSA_PKCS1_SHA256,
        &rng,
        &auth_attrs_der,
        &mut signature_bytes,
    )?;

    let si_ver = simple_asn1::to_der(&ASN1Block::Integer(0, BigInt::from(1)))
        .map_err(|e| SignerError::Config(format!("ASN1 encoding error for version: {}", e)))?;
    let issuer_blocks = simple_asn1::from_der(issuer_der)
        .map_err(|e| SignerError::Config(format!("Issuer parse error: {}", e)))?;
    let iasn = ASN1Block::Sequence(
        0,
        vec![
            issuer_blocks.into_iter().next().ok_or_else(|| {
                SignerError::Config("No issuer block found in certificate".to_string())
            })?,
            ASN1Block::Integer(0, serial_bigint),
        ],
    );
    let si_iasn = simple_asn1::to_der(&iasn)
        .map_err(|e| SignerError::Config(format!("ASN1 encoding error for issuer: {}", e)))?;
    let si_da = simple_asn1::to_der(&ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::ObjectIdentifier(0, oid_sha256.clone()),
            ASN1Block::Null(0),
        ],
    ))
    .map_err(|e| SignerError::Config(format!("ASN1 encoding error for digest algorithm: {}", e)))?;
    let si_ea = simple_asn1::to_der(&ASN1Block::Sequence(
        0,
        vec![ASN1Block::ObjectIdentifier(0, oid_rsa), ASN1Block::Null(0)],
    ))
    .map_err(|e| {
        SignerError::Config(format!(
            "ASN1 encoding error for encryption algorithm: {}",
            e
        ))
    })?;
    let si_ed = simple_asn1::to_der(&ASN1Block::OctetString(0, signature_bytes))
        .map_err(|e| SignerError::Config(format!("ASN1 encoding error for signature: {}", e)))?;

    let mut si_content = Vec::new();
    si_content.extend(si_ver);
    si_content.extend(si_iasn);
    si_content.extend(si_da);
    si_content.extend(auth_attrs_implicit);
    si_content.extend(si_ea);
    si_content.extend(si_ed);
    let signer_info = wrap_tag(0x30, &si_content);

    let sd_ver = simple_asn1::to_der(&ASN1Block::Integer(0, BigInt::from(1))).map_err(|e| {
        SignerError::Config(format!(
            "ASN1 encoding error for signed data version: {}",
            e
        ))
    })?;
    let da_set = ASN1Block::Set(
        0,
        vec![ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::ObjectIdentifier(0, oid_sha256),
                ASN1Block::Null(0),
            ],
        )],
    );
    let sd_da = simple_asn1::to_der(&da_set).map_err(|e| {
        SignerError::Config(format!(
            "ASN1 encoding error for digest algorithm set: {}",
            e
        ))
    })?;
    let eci = ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, oid_data)]);
    let sd_eci = simple_asn1::to_der(&eci)
        .map_err(|e| SignerError::Config(format!("ASN1 encoding error for content info: {}", e)))?;
    let sd_certs = wrap_tag(0xA0, cert_der);
    let sd_si = wrap_tag(0x31, &signer_info);

    let mut sd_content = Vec::new();
    sd_content.extend(sd_ver);
    sd_content.extend(sd_da);
    sd_content.extend(sd_eci);
    sd_content.extend(sd_certs);
    sd_content.extend(sd_si);
    let signed_data = wrap_tag(0x30, &sd_content);

    let ci_oid =
        simple_asn1::to_der(&ASN1Block::ObjectIdentifier(0, oid_signed_data)).map_err(|e| {
            SignerError::Config(format!("ASN1 encoding error for content identifier: {}", e))
        })?;
    let ci_content = wrap_tag(0xA0, &signed_data);

    let mut ci_final = Vec::new();
    ci_final.extend(ci_oid);
    ci_final.extend(ci_content);

    Ok(wrap_tag(0x30, &ci_final))
}
