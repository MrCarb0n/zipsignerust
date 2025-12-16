use crate::{crypto::CryptoEngine, error::SignerError, keys::KeyChain};
use simple_asn1::{ASN1Block, ASN1Class, BigInt, BigUint};
use x509_parser::prelude::*;

/// Generates a PKCS#7 SignedData structure (CERT.RSA)
pub fn gen_rsa(keys: &KeyChain, sf: &[u8]) -> Result<Vec<u8>, SignerError> {
    use ring::signature;

    let key_pair = keys.private_key.as_ref().ok_or(SignerError::Config(
        "Private key missing for signing".into(),
    ))?;

    let cert_der = keys.cert_der.as_ref().ok_or(SignerError::Config(
        "Certificate missing for signing".into(),
    ))?;

    // 1. Parse Certificate to get Issuer Name and Serial Number
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| SignerError::Config(format!("Failed to parse cert for PKCS7: {}", e)))?;

    // Extract Issuer Name and Serial Number
    let issuer_der = cert.tbs_certificate.issuer.as_raw();
    let serial_bytes = cert.tbs_certificate.serial.to_bytes_be();
    let serial_bigint = BigInt::from_signed_bytes_be(&serial_bytes);

    // 2. Define OIDs
    let oid_signed_data = simple_asn1::oid!(1, 2, 840, 113549, 1, 7, 2); // 1.2.840.113549.1.7.2 signedData
    let oid_data = simple_asn1::oid!(1, 2, 840, 113549, 1, 7, 1); // 1.2.840.113549.1.7.1 data
    let oid_sha256 = simple_asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 1); // 2.16.840.1.101.3.4.2.1 sha256
    let oid_rsa = simple_asn1::oid!(1, 2, 840, 113549, 1, 1, 1); // 1.2.840.113549.1.1.1 rsaEncryption

    // 3. Create authenticated attributes (contentType and messageDigest)
    // This is required for proper Android JAR signature verification
    let auth_attrs = vec![
        // contentType attribute (1.2.840.113549.1.9.3)
        ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1, 2, 840, 113549, 1, 9, 3)), // contentType OID
                ASN1Block::Set(
                    0,
                    vec![
                        ASN1Block::ObjectIdentifier(0, oid_data.clone()), // data content type
                    ],
                ),
            ],
        ),
        // messageDigest attribute (1.2.840.113549.1.9.4)
        ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1, 2, 840, 113549, 1, 9, 4)), // messageDigest OID
                ASN1Block::Set(
                    0,
                    vec![ASN1Block::OctetString(
                        0,
                        CryptoEngine::compute_sha1(sf).as_bytes().to_vec(),
                    )],
                ),
            ],
        ),
    ];

    // 4. Sign the DER encoding of the authenticated attributes
    // This is the correct way for PKCS#7 with authenticated attributes
    let attrs_der = simple_asn1::to_der(&ASN1Block::Set(0, auth_attrs.clone())).map_err(|e| {
        SignerError::Config(format!("ASN1 encode error for authenticated attrs: {}", e))
    })?;

    let mut signature_bytes = vec![0u8; key_pair.public().modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    key_pair.sign(
        &signature::RSA_PKCS1_SHA256,
        &rng,
        &attrs_der,
        &mut signature_bytes,
    )?;

    // 5. Build the PKCS#7 SignedData structure - Proper authenticated JAR signature format
    let signed_data_content = vec![
        ASN1Block::Integer(0, BigInt::from(1u32)), // version - with authenticated attributes, it should be 1
        ASN1Block::Set(
            0,
            vec![
                // digestAlgorithms
                ASN1Block::Sequence(
                    0,
                    vec![
                        ASN1Block::ObjectIdentifier(0, oid_sha256.clone()),
                        ASN1Block::Null(0),
                    ],
                ),
            ],
        ),
        // encapContentInfo - Content is omitted for JAR signatures
        ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::ObjectIdentifier(0, oid_data),
                // Content is omitted per JAR signature specification
            ],
        ),
        // certificates [0] EXPLICIT SET OF Certificate
        ASN1Block::Explicit(
            ASN1Class::ContextSpecific,
            0,
            BigUint::from(0u32),
            Box::new(ASN1Block::Set(
                0,
                vec![
                    // Decode certificate DER to ASN.1 blocks
                    simple_asn1::from_der(cert_der)
                        .map_err(|e| {
                            SignerError::Config(format!("Failed to decode certificate: {}", e))
                        })?
                        .into_iter()
                        .next()
                        .ok_or(SignerError::Config("Failed to parse certificate".into()))?,
                ],
            )),
        ),
        // signerInfos
        ASN1Block::Set(
            0,
            vec![ASN1Block::Sequence(
                0,
                vec![
                    // SignerInfo
                    ASN1Block::Integer(0, BigInt::from(1u32)), // version - for PKCS#7 with authenticated attributes
                    // issuerAndSerialNumber
                    ASN1Block::Sequence(
                        0,
                        vec![
                            // Parse the issuer DER to get the ASN1 structure
                            simple_asn1::from_der(issuer_der)
                                .map_err(|e| {
                                    SignerError::Config(format!("Failed to decode issuer: {}", e))
                                })?
                                .into_iter()
                                .next()
                                .ok_or(SignerError::Config("Failed to parse issuer".into()))?,
                            ASN1Block::Integer(0, serial_bigint),
                        ],
                    ),
                    // digestAlgorithm
                    ASN1Block::Sequence(
                        0,
                        vec![
                            ASN1Block::ObjectIdentifier(0, oid_sha256.clone()),
                            ASN1Block::Null(0),
                        ],
                    ),
                    // authenticatedAttributes - the attributes that were signed
                    ASN1Block::Set(0, auth_attrs),
                    // digestEncryptionAlgorithm
                    ASN1Block::Sequence(
                        0,
                        vec![
                            ASN1Block::ObjectIdentifier(0, oid_rsa), // rsaEncryption
                            ASN1Block::Null(0),
                        ],
                    ),
                    // encryptedDigest - signature of the authenticated attributes
                    ASN1Block::OctetString(0, signature_bytes),
                ],
            )],
        ),
    ];

    // Complete structure: ContentInfo containing SignedData
    let content_info = vec![
        ASN1Block::ObjectIdentifier(0, oid_signed_data), // signedData OID
        ASN1Block::Explicit(
            ASN1Class::ContextSpecific,
            0,
            BigUint::from(0u32),
            Box::new(ASN1Block::Sequence(0, signed_data_content)),
        ),
    ];

    simple_asn1::to_der(&ASN1Block::Sequence(0, content_info))
        .map_err(|e| SignerError::Config(format!("ASN1 encode error: {}", e)))
}
