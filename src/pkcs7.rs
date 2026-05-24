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
use simple_asn1::{ASN1Block, BigInt};
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

fn parse_der_tlv(data: &[u8]) -> Result<(u8, Vec<u8>, &[u8]), SignerError> {
    if data.is_empty() {
        return Err(SignerError::Validation("Empty DER data".into()));
    }
    let tag = data[0];
    let (len, after_len) = if data[1] < 0x80 {
        (data[1] as usize, &data[2..])
    } else {
        let num_bytes = (data[1] & 0x7F) as usize;
        if data.len() < 2 + num_bytes {
            return Err(SignerError::Validation("Truncated DER length".into()));
        }
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | data[2 + i] as usize;
        }
        (l, &data[2 + num_bytes..])
    };
    if after_len.len() < len {
        return Err(SignerError::Validation("Truncated DER value".into()));
    }
    let value = after_len[..len].to_vec();
    let rest = &after_len[len..];
    Ok((tag, value, rest))
}

fn skip_der_element(data: &[u8]) -> Result<&[u8], SignerError> {
    let (_, _, rest) = parse_der_tlv(data)?;
    Ok(rest)
}

fn find_der_element(data: &[u8], target_tag: u8) -> Result<(Vec<u8>, &[u8]), SignerError> {
    let mut remaining = data;
    while !remaining.is_empty() {
        let (tag, value, rest) = parse_der_tlv(remaining)?;
        if tag == target_tag {
            return Ok((value, rest));
        }
        remaining = rest;
    }
    Err(SignerError::Validation(format!("DER tag 0x{target_tag:02X} not found")))
}

/// PKCS7 signer info extracted from a signature blob.
pub struct SignerInfo {
    pub signature: Vec<u8>,
    pub auth_attrs_der: Vec<u8>,
    pub message_digest: Vec<u8>,
}

/// Extract PKCS7 signer info: signature_bytes, auth_attrs_der_with_set_tag, expected_sf_digest
pub fn extract_signer_info(pkcs7_der: &[u8]) -> Result<SignerInfo, SignerError> {
    let (_, ci_content, _) = parse_der_tlv(pkcs7_der)?;
    let (_oid, rest) = find_der_element(&ci_content, 0x06)?;
    let (sd_raw, _) = find_der_element(rest, 0xA0)?;
    let (_, sd_content, _) = parse_der_tlv(&sd_raw)?;

    let mut cursor = &sd_content[..];
    cursor = skip_der_element(cursor)?;
    cursor = skip_der_element(cursor)?;
    cursor = skip_der_element(cursor)?;
    if cursor.first() == Some(&0xA0) {
        cursor = skip_der_element(cursor)?;
    }
    let (si_set, _) = find_der_element(cursor, 0x31)?;
    let (_, si_content, _) = parse_der_tlv(&si_set)?;

    cursor = &si_content[..];
    cursor = skip_der_element(cursor)?;
    cursor = skip_der_element(cursor)?;
    cursor = skip_der_element(cursor)?;
    let (auth_attrs_raw, rest) = find_der_element(cursor, 0xA0)?;
    cursor = rest;
    cursor = skip_der_element(cursor)?;
    let (sig_octet, _) = find_der_element(cursor, 0x04)?;

    let auth_attrs_with_set = wrap_tag(0x31, &auth_attrs_raw);

    let digest = extract_message_digest(&auth_attrs_raw)?;

    Ok(SignerInfo {
        signature: sig_octet,
        auth_attrs_der: auth_attrs_with_set,
        message_digest: digest,
    })
}

fn extract_message_digest(auth_attrs_raw: &[u8]) -> Result<Vec<u8>, SignerError> {
    let mut cursor = auth_attrs_raw;
    while !cursor.is_empty() {
        let (tag, value, rest) = parse_der_tlv(cursor)?;
        if tag == 0x30 {
            if let Ok(digest) = try_extract_digest_from_sequence(&value) {
                return Ok(digest);
            }
        }
        cursor = rest;
    }
    Err(SignerError::Validation("messageDigest not found in authenticated attributes".into()))
}

fn try_extract_digest_from_sequence(seq_content: &[u8]) -> Result<Vec<u8>, SignerError> {
    let (tag, oid_value, rest) = parse_der_tlv(seq_content)?;
    if tag != 0x06 {
        return Err(SignerError::Validation("Expected OID in attribute SEQUENCE".into()));
    }
    let msg_digest_oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
    if oid_value != msg_digest_oid {
        return Err(SignerError::Validation("Not messageDigest OID".into()));
    }
    let (set_tag, set_content, _) = parse_der_tlv(rest)?;
    if set_tag != 0x31 {
        return Err(SignerError::Validation("Expected SET after OID".into()));
    }
    let (octet_tag, octet_value, _) = parse_der_tlv(&set_content)?;
    if octet_tag != 0x04 {
        return Err(SignerError::Validation("Expected OCTET STRING".into()));
    }
    Ok(octet_value)
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
            issuer_blocks.into_iter().next()
                .ok_or_else(|| SignerError::Config("No issuer block found in certificate".to_string()))?,
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
    .map_err(|e| SignerError::Config(format!("ASN1 encoding error for encryption algorithm: {}", e)))?;
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

    let sd_ver = simple_asn1::to_der(&ASN1Block::Integer(0, BigInt::from(1)))
        .map_err(|e| SignerError::Config(format!("ASN1 encoding error for signed data version: {}", e)))?;
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
    let sd_da = simple_asn1::to_der(&da_set)
        .map_err(|e| SignerError::Config(format!("ASN1 encoding error for digest algorithm set: {}", e)))?;
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

    let ci_oid = simple_asn1::to_der(&ASN1Block::ObjectIdentifier(0, oid_signed_data))
        .map_err(|e| SignerError::Config(format!("ASN1 encoding error for content identifier: {}", e)))?;
    let ci_content = wrap_tag(0xA0, &signed_data);

    let mut ci_final = Vec::new();
    ci_final.extend(ci_oid);
    ci_final.extend(ci_content);

    Ok(wrap_tag(0x30, &ci_final))
}
