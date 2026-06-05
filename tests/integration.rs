use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::Pem;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;
use zipsignerust::{
    certificate::{DEFAULT_CERT_SHA256, PUBLIC_KEY},
    crypto::CryptoEngine,
    error::SignerError,
    keys::KeyChain,
    processor::ArtifactProcessor,
    ui::Ui,
    verification::{ArtifactVerifier, ERR_NO_RSA_SIGNATURE},
};

fn create_test_zip(dir: &Path, name: &str, files: &[(&str, &[u8])]) -> std::path::PathBuf {
    let path = dir.join(name);
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::<()>::default().compression_method(CompressionMethod::Stored);

    for (name, content) in files {
        zip.start_file(name, opts).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap();
    path
}

fn silent_ui() -> Ui {
    Ui::silent()
}

fn signed_zip_contains_meta_inf(path: &Path) -> bool {
    let file = std::fs::File::open(path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let sig_names: [&str; 3] = [
        zipsignerust::MANIFEST_NAME,
        zipsignerust::CERT_SF_NAME,
        zipsignerust::CERT_RSA_NAME,
    ];
    for i in 0..archive.len() {
        let name = archive.by_index(i).unwrap().name().to_string();
        if sig_names.contains(&name.as_str()) {
            return true;
        }
    }
    false
}

#[test]
fn test_sign_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let input = create_test_zip(
        tmp.path(),
        "input.zip",
        &[
            ("file1.txt", b"hello world"),
            ("file2.txt", b"test data 123"),
            ("sub/file3.txt", b"nested content"),
        ],
    );
    let signed_path = tmp.path().join("signed.zip");
    let ui = silent_ui();

    let key_chain = KeyChain::new(None, None, &ui).unwrap();
    let nested =
        ArtifactProcessor::compute_digests_prepare_nested(&input, &key_chain, &ui).unwrap();

    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &signed_path,
        &key_chain,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();

    assert!(signed_path.exists(), "signed output must exist");
    assert!(
        signed_path.metadata().unwrap().len() > input.metadata().unwrap().len(),
        "signed file larger due to signature entries"
    );
    assert!(
        signed_zip_contains_meta_inf(&signed_path),
        "signed zip must contain META-INF signature files"
    );
    assert!(
        !signed_zip_contains_meta_inf(&input),
        "unsigned input must NOT contain META-INF signature files"
    );
}

#[test]
fn test_signed_zip_reads_back() {
    let tmp = TempDir::new().unwrap();
    let input = create_test_zip(tmp.path(), "input.zip", &[("data.bin", b"payload")]);
    let signed = tmp.path().join("out.zip");
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &signed,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();

    let file = std::fs::File::open(&signed).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let names: Vec<String> = (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(names.contains(&"META-INF/MANIFEST.MF".to_string()));
    assert!(names.contains(&"META-INF/CERT.SF".to_string()));
    assert!(names.contains(&"META-INF/CERT.RSA".to_string()));
    assert!(names.contains(&"data.bin".to_string()));
}

#[test]
fn test_verify_rejects_unsigned_zip() {
    let tmp = TempDir::new().unwrap();
    let input = create_test_zip(tmp.path(), "unsigned.zip", &[("a.txt", b"data")]);
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();

    let result = ArtifactVerifier::verify(&input, &keys, &ui);
    match result {
        Err(SignerError::Validation(msg)) => {
            assert!(
                msg.contains(ERR_NO_RSA_SIGNATURE),
                "expected '{}' error, got: {}",
                ERR_NO_RSA_SIGNATURE,
                msg
            );
        }
        other => panic!(
            "expected Validation error for unsigned zip, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_sign_and_verify_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let input = create_test_zip(
        tmp.path(),
        "input.zip",
        &[("a.txt", b"hello"), ("b.txt", b"world")],
    );
    let signed = tmp.path().join("signed.zip");
    let ui = silent_ui();

    let keys = KeyChain::new(None, None, &ui).unwrap();
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &signed,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();

    let verify_keys = KeyChain::new(None, None, &ui).unwrap();
    let valid = ArtifactVerifier::verify(&signed, &verify_keys, &ui).unwrap();
    assert!(valid, "sign-then-verify round-trip must pass");
}

#[test]
fn test_sign_large_number_of_files() {
    let tmp = TempDir::new().unwrap();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..50 {
        let name = format!("dir/file_{}.bin", i);
        let content = vec![i as u8; 100];
        files.push((name, content));
    }

    let file_refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_slice()))
        .collect();

    let input = create_test_zip(tmp.path(), "many.zip", &file_refs);
    let signed = tmp.path().join("many_signed.zip");
    let ui = silent_ui();

    let keys = KeyChain::new(None, None, &ui).unwrap();
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &signed,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();

    assert!(
        signed_zip_contains_meta_inf(&signed),
        "large signed zip must contain META-INF"
    );
}

#[test]
fn test_compute_sha1_consistency() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let digest1 = CryptoEngine::compute_sha1(data);
    let digest2 = CryptoEngine::compute_sha1(data);
    assert_eq!(digest1, digest2, "SHA1 must be deterministic");
}

#[test]
fn test_key_chain_default_keys() {
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    assert!(keys.private_key.is_some(), "default private key must load");
    assert!(keys.public_key.is_some(), "default public key must load");
    assert!(keys.cert_der.is_some(), "default certificate must load");
}

#[test]
fn test_verify_corrupted_signature_rejected() {
    let tmp = TempDir::new().unwrap();
    let input = create_test_zip(tmp.path(), "good.zip", &[("f.txt", b"data")]);
    let signed = tmp.path().join("good_signed.zip");
    let ui = silent_ui();

    let keys = KeyChain::new(None, None, &ui).unwrap();
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &signed,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();

    // Corrupt a known byte inside the user file. Stored as `data` in the
    // input zip, the literal bytes survive into the signed archive under
    // `f.txt` (uncompressed). Flipping one bit forces a SHA digest mismatch
    // in the manifest, which is exactly the path we want to exercise —
    // the previous middle-of-file corruption could hit any zip structure
    // (headers, signature, padding) and pass for the wrong reason.
    let mut bytes = std::fs::read(&signed).unwrap();
    let pos = bytes
        .windows(4)
        .position(|w| w == b"data")
        .expect("plain `data` payload must be present in stored-mode archive");
    bytes[pos] ^= 0xFF;
    std::fs::write(&signed, &bytes).unwrap();

    let verify_keys = KeyChain::new(None, None, &ui).unwrap();
    let result = ArtifactVerifier::verify(&signed, &verify_keys, &ui);
    assert!(result.is_err(), "corrupted archive must fail verification");
}

#[test]
fn test_sign_is_deterministic() {
    // Regression: signing the same input twice must produce byte-identical
    // archives. Previously inner file mtimes used SystemTime::now() which
    // drifted between runs.
    let tmp = TempDir::new().unwrap();
    let input = create_test_zip(
        tmp.path(),
        "input.zip",
        &[
            ("file1.txt", b"hello world"),
            ("file2.txt", b"another file"),
            ("sub/file3.txt", b"nested content"),
        ],
    );
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();

    let out1 = tmp.path().join("signed_a.zip");
    let out2 = tmp.path().join("signed_b.zip");
    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &out1,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &out2,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();

    let a = std::fs::read(&out1).unwrap();
    let b = std::fs::read(&out2).unwrap();
    assert_eq!(
        a, b,
        "signing the same input twice must produce identical bytes"
    );
}

// --- T3: wrap_msg stress tests ---
//
// These exercise Ui::wrap_msg with inputs that have historically been
// sources of off-by-one bugs in terminal line wrapping. wrap_msg takes
// (msg, indent) and the wrap width is taken from the COLUMNS env var.
// We set COLUMNS explicitly so the tests are deterministic.

fn wrap_at_cols(text: &str, indent: usize, cols: usize) -> String {
    std::env::set_var("COLUMNS", cols.to_string());
    let ui = Ui::silent();
    ui.wrap_msg(text, indent)
}

#[test]
fn test_wrap_msg_empty_input() {
    assert_eq!(wrap_at_cols("", 0, 80), "");
}

#[test]
fn test_wrap_msg_very_narrow_columns_clamps() {
    // The function clamps effective width to a minimum of 10 chars to
    // avoid pathological wrapping. With COLUMNS=1, the effective width
    // is 10, so "abc" fits on one line and is not broken per-char.
    let out = wrap_at_cols("abc", 0, 1);
    assert_eq!(out, "abc");
}

#[test]
fn test_wrap_msg_unicode_codepoints_preserved() {
    // Each char is one codepoint; wrap should treat them individually
    // and the round-trip must preserve all codepoints (no truncation,
    // no mojibake from byte slicing).
    let out = wrap_at_cols("héllo wörld", 0, 12);
    let rejoined: String = out.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(rejoined, "héllo wörld");
}

#[test]
fn test_wrap_msg_exact_width_no_break() {
    // Word fits exactly; should not be split or duplicated.
    let out = wrap_at_cols("hello", 0, 5);
    assert_eq!(out, "hello");
}

#[test]
fn test_wrap_msg_long_word_is_broken() {
    // 20-char word with width=10 must be broken across at least 2 lines
    // and round-trip back to the original when we rejoin.
    let out = wrap_at_cols("supercalifragilistic", 0, 10);
    let rejoined: String = out.replace('\n', "");
    assert_eq!(rejoined, "supercalifragilistic");
    assert!(out.split('\n').count() >= 2);
}

#[test]
fn test_wrap_msg_preserves_word_boundaries() {
    // "the quick brown fox" with width=10: the algorithm packs words
    // greedily, so the result should be a valid reordering of the words.
    let out = wrap_at_cols("the quick brown fox", 0, 10);
    let rejoined: String = out.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(rejoined, "the quick brown fox");
}

#[test]
fn test_wrap_msg_indent_shrinks_effective_width() {
    // With COLUMNS=20 and indent=8, effective width is 12. A 20-char
    // word must wrap.
    let out = wrap_at_cols("supercalifragilistic", 8, 20);
    let rejoined: String = out.replace('\n', "");
    assert_eq!(rejoined, "supercalifragilistic");
    assert!(out.split('\n').count() >= 2);
}

#[test]
fn test_wrap_msg_huge_indent_does_not_panic() {
    // Indent larger than COLUMNS: effective width must clamp to >=10.
    // Whatever happens, the function must not panic and must not lose
    // any content.
    let out = wrap_at_cols("hello world", 1000, 20);
    let rejoined: String = out.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(rejoined, "hello world");
}

#[test]
fn test_default_cert_fingerprint_matches() {
    // Verify that DEFAULT_CERT_SHA256 matches the actual PUBLIC_KEY fingerprint.
    // If this test fails, the embedded certificate has changed and
    // DEFAULT_CERT_SHA256 in src/certificate.rs must be updated.
    let cert_pem = PUBLIC_KEY;
    let mut pem_iter = Pem::iter_from_buffer(cert_pem.as_bytes());
    let pem = pem_iter.next().expect("valid PEM").expect("PEM block");
    let (_, cert) = parse_x509_certificate(&pem.contents).expect("parse X509");
    // Compute SHA-256 fingerprint of the certificate DER bytes (RFC 5280)
    let der = cert.as_raw();
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let fingerprint = digest
        .as_ref()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":");
    let expected = DEFAULT_CERT_SHA256;
    assert_eq!(
        fingerprint, expected,
        "DEFAULT_CERT_SHA256 mismatch: got {}, expected {}",
        fingerprint, expected
    );
}
