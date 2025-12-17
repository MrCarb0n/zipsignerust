/*
 * ZipSigner Rust v1.0.0
 * Copyright (c) 2026 Tiash H Kabir / @MrCarb0n.
 * Licensed under the MIT License.
 */

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

    let si_ver = simple_asn1::to_der(&ASN1Block::Integer(0, BigInt::from(1))).unwrap();
    let issuer_blocks = simple_asn1::from_der(issuer_der)
        .map_err(|e| SignerError::Config(format!("Issuer parse error: {}", e)))?;
    let iasn = ASN1Block::Sequence(
        0,
        vec![
            issuer_blocks.into_iter().next().unwrap(),
            ASN1Block::Integer(0, serial_bigint),
        ],
    );
    let si_iasn = simple_asn1::to_der(&iasn).unwrap();
    let si_da = simple_asn1::to_der(&ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::ObjectIdentifier(0, oid_sha256.clone()),
            ASN1Block::Null(0),
        ],
    ))
    .unwrap();
    let si_ea = simple_asn1::to_der(&ASN1Block::Sequence(
        0,
        vec![ASN1Block::ObjectIdentifier(0, oid_rsa), ASN1Block::Null(0)],
    ))
    .unwrap();
    let si_ed = simple_asn1::to_der(&ASN1Block::OctetString(0, signature_bytes)).unwrap();

    let mut si_content = Vec::new();
    si_content.extend(si_ver);
    si_content.extend(si_iasn);
    si_content.extend(si_da);
    si_content.extend(auth_attrs_implicit);
    si_content.extend(si_ea);
    si_content.extend(si_ed);
    let signer_info = wrap_tag(0x30, &si_content);

    let sd_ver = simple_asn1::to_der(&ASN1Block::Integer(0, BigInt::from(1))).unwrap();
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
    let sd_da = simple_asn1::to_der(&da_set).unwrap();
    let eci = ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, oid_data)]);
    let sd_eci = simple_asn1::to_der(&eci).unwrap();
    let sd_certs = wrap_tag(0xA0, cert_der);
    let sd_si = wrap_tag(0x31, &signer_info);

    let mut sd_content = Vec::new();
    sd_content.extend(sd_ver);
    sd_content.extend(sd_da);
    sd_content.extend(sd_eci);
    sd_content.extend(sd_certs);
    sd_content.extend(sd_si);
    let signed_data = wrap_tag(0x30, &sd_content);

    let ci_oid = simple_asn1::to_der(&ASN1Block::ObjectIdentifier(0, oid_signed_data)).unwrap();
    let ci_content = wrap_tag(0xA0, &signed_data);

    let mut ci_final = Vec::new();
    ci_final.extend(ci_oid);
    ci_final.extend(ci_content);

    Ok(wrap_tag(0x30, &ci_final))
}
