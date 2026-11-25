use std::io::{Read, Write};
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

    let mut wrong = verify_keys;
    let mut wrong_key = wrong.public_key.as_ref().unwrap().as_ref().to_vec();
    let middle = wrong_key.len() / 2;
    wrong_key[middle] ^= 1;
    wrong.public_key = Some(ring::signature::UnparsedPublicKey::new(
        zipsignerust::keys::RSA_VERIFICATION_ALGORITHM,
        wrong_key,
    ));
    let err = ArtifactVerifier::verify_with_pin(&signed, &wrong, &ui, Some(DEFAULT_CERT_SHA256))
        .unwrap_err();
    assert!(err.to_string().contains("trusted public key"));
}

#[test]
fn test_signing_does_not_clobber_input_or_existing_output() {
    let tmp = TempDir::new().unwrap();
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let input = create_test_zip(tmp.path(), "input.zip", &[("data.txt", b"original")]);
    let original = std::fs::read(&input).unwrap();
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    assert!(ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &input,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .is_err());
    assert_eq!(std::fs::read(&input).unwrap(), original);

    let sign = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_zipsignerust"))
            .current_dir(tmp.path())
            .arg("sign")
            .args(args)
            .output()
            .unwrap()
    };
    let output = tmp.path().join("out.zip");
    std::fs::write(&output, b"keep me").unwrap();
    assert!(!sign(&["input.zip", "out.zip"]).status.success());
    assert_eq!(std::fs::read(output).unwrap(), b"keep me");
    #[cfg(unix)]
    {
        let alias = tmp.path().join("alias.zip");
        std::fs::hard_link(&input, &alias).unwrap();
        assert!(!sign(&["--overwrite", "input.zip", "alias.zip"])
            .status
            .success());
        assert_eq!(std::fs::read(alias).unwrap(), original);
    }

    assert!(sign(&["--inplace", "input.zip"]).status.success());
    assert!(ArtifactVerifier::verify(&input, &keys, &ui).unwrap());
    assert!(sign(&["--inplace", "input.zip"]).status.success());
    let backups: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "bak"))
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    assert_eq!(backups.len(), 2);
    assert!(backups.contains(&original));

    let invalid = create_test_zip(tmp.path(), "invalid.zip", &[("bad\nname", b"keep me")]);
    let original = std::fs::read(&invalid).unwrap();
    assert!(!sign(&["--inplace", "invalid.zip"]).status.success());
    assert_eq!(std::fs::read(invalid).unwrap(), original);
}

#[test]
fn test_valid_zip64_directory() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("zip64.zip");
    let mut zip = ZipWriter::new(std::fs::File::create(&path).unwrap());
    zip.set_zip64_comment(Some("ZIP64"));
    zip.start_file("payload.txt", FileOptions::<()>::default())
        .unwrap();
    zip.write_all(b"payload").unwrap();
    zip.finish().unwrap();
    ArtifactProcessor::verify_zip_integrity(&path).unwrap();
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

#[test]
fn test_sign_zip_with_nested_zip_three_levels() {
    // Regression: the writer's scratch buffer used to be a thread_local,
    // which panicked when signing a zip inside a zip inside a zip.
    let tmp = TempDir::new().unwrap();
    let l3 = create_test_zip(tmp.path(), "l3.zip", &[("deep.txt", b"deep")]);
    let l3_bytes = std::fs::read(&l3).unwrap();
    let l2 = create_test_zip(
        tmp.path(),
        "l2.zip",
        &[("l3.zip", l3_bytes.as_slice()), ("b.txt", b"b")],
    );
    let l2_bytes = std::fs::read(&l2).unwrap();
    let l1 = create_test_zip(
        tmp.path(),
        "l1.zip",
        &[("l2.zip", l2_bytes.as_slice()), ("a.txt", b"a")],
    );

    let signed = tmp.path().join("signed.zip");
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&l1, &keys, &ui).unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &l1,
        &signed,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();

    assert!(ArtifactVerifier::verify(&signed, &keys, &ui).unwrap());

    // The embedded second-level zip must carry a valid signature of its own.
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&signed).unwrap()).unwrap();
    let mut inner = Vec::new();
    archive
        .by_name("l2.zip")
        .unwrap()
        .read_to_end(&mut inner)
        .unwrap();
    let inner_path = tmp.path().join("inner-l2.zip");
    std::fs::write(&inner_path, &inner).unwrap();
    assert!(ArtifactVerifier::verify(&inner_path, &keys, &ui).unwrap());
}

#[test]
fn test_verify_legacy_sha1_signed_archive() {
    // Fixture generated by v1.0.0, which wrote SHA1-Digest manifest fields.
    // Current builds write SHA-256 but must still accept SHA-1 on read.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-sha1-signed.zip");
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    assert!(ArtifactVerifier::verify(&path, &keys, &ui).unwrap());
}

#[test]
fn test_verify_jarsigner_sha384_signed_archive() {
    // Fixture signed by JDK jarsigner with -digestalg SHA-384 (its default for
    // RSA keys); long digest values wrap at 72 bytes in MANIFEST.MF / CERT.SF.
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/jarsigner-sha384-signed.zip");
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    assert!(ArtifactVerifier::verify(&fixture, &keys, &ui).unwrap());

    // Tampering with a stored payload byte must still be caught.
    let tmp = TempDir::new().unwrap();
    let tampered = tmp.path().join("tampered.zip");
    let mut bytes = std::fs::read(&fixture).unwrap();
    let pos = bytes
        .windows(5)
        .position(|w| w == b"hello")
        .expect("stored payload must be present");
    bytes[pos] ^= 0xFF;
    std::fs::write(&tampered, &bytes).unwrap();
    assert!(ArtifactVerifier::verify(&tampered, &keys, &ui).is_err());
}

#[test]
fn test_verify_jarsigner_sha1_signed_archive() {
    // Legacy SHA-1 PKCS7 signature and manifest digests from jarsigner.
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/jarsigner-sha1-signed.zip");
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    assert!(ArtifactVerifier::verify(&path, &keys, &ui).unwrap());
}

fn dev_key_cert(tmp: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let key = tmp.join("dev.key.pem");
    let cert = tmp.join("dev.cert.pem");
    std::fs::write(&key, zipsignerust::certificate::PRIVATE_KEY).unwrap();
    std::fs::write(&cert, zipsignerust::certificate::PUBLIC_KEY).unwrap();
    (key, cert)
}

fn openssl_signed_zip(
    tmp: &Path,
    name: &str,
    mf: &[u8],
    sf: &[u8],
    sig_name: &str,
    noattr: bool,
) -> std::path::PathBuf {
    let (key, cert) = dev_key_cert(tmp);
    let sf_path = tmp.join(format!("{name}.SF"));
    let der_path = tmp.join(format!("{name}.der"));
    std::fs::write(&sf_path, sf).unwrap();
    let mut cmd = std::process::Command::new("openssl");
    cmd.args(["cms", "-sign", "-binary", "-md", "sha256", "-in"])
        .arg(&sf_path)
        .args(["-signer"])
        .arg(&cert)
        .args(["-inkey"])
        .arg(&key)
        .args(["-outform", "DER", "-out"])
        .arg(&der_path);
    if noattr {
        cmd.arg("-noattr");
    }
    let status = cmd.output().expect("openssl");
    assert!(
        status.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let sig = std::fs::read(&der_path).unwrap();
    let out = tmp.join(format!("{name}.zip"));
    let file = std::fs::File::create(&out).unwrap();
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::<()>::default().compression_method(CompressionMethod::Stored);
    zip.start_file("a.txt", opts).unwrap();
    zip.write_all(b"hello").unwrap();
    zip.start_file("META-INF/MANIFEST.MF", opts).unwrap();
    zip.write_all(mf).unwrap();
    zip.start_file(format!("META-INF/{sig_name}.SF"), opts)
        .unwrap();
    zip.write_all(sf).unwrap();
    zip.start_file(format!("META-INF/{sig_name}.RSA"), opts)
        .unwrap();
    zip.write_all(&sig).unwrap();
    zip.finish().unwrap();
    out
}

#[test]
fn test_verify_rejects_duplicate_entries() {
    let tmp = TempDir::new().unwrap();
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let input = create_test_zip(tmp.path(), "in.zip", &[("a.txt", b"hello")]);
    let signed = tmp.path().join("signed.zip");
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
    let dup = tmp.path().join("dup.zip");
    let script = format!(
        "import zipfile,warnings\nwarnings.simplefilter('ignore')\nwith zipfile.ZipFile({:?}) as src, zipfile.ZipFile({:?},'w') as dst:\n    dst.writestr('a.txt', b'tampered')\n    for f in src.infolist():\n        dst.writestr(f, src.read(f))\n",
        signed.to_string_lossy(),
        dup.to_string_lossy()
    );
    let status = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(ArtifactVerifier::verify(&dup, &keys, &ui).is_err());
}

#[test]
fn test_rejects_deeply_nested_signature_asn1() {
    let tmp = TempDir::new().unwrap();
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let mut b = vec![0x05, 0x00];
    for _ in 0..200 {
        let len = b.len();
        let mut enc = Vec::new();
        if len < 128 {
            enc.push(len as u8);
        } else {
            enc.push(0x82);
            enc.push((len >> 8) as u8);
            enc.push((len & 0xff) as u8);
        }
        let mut s = vec![0x30];
        s.extend(enc);
        s.extend(b);
        b = s;
    }
    let out = tmp.path().join("deep.zip");
    let file = std::fs::File::create(&out).unwrap();
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::<()>::default().compression_method(CompressionMethod::Stored);
    zip.start_file("META-INF/CERT.RSA", opts).unwrap();
    zip.write_all(&b).unwrap();
    zip.start_file("META-INF/CERT.SF", opts).unwrap();
    zip.write_all(b"Signature-Version: 1.0\r\n\r\n").unwrap();
    zip.start_file("META-INF/MANIFEST.MF", opts).unwrap();
    zip.write_all(b"Manifest-Version: 1.0\r\n\r\n").unwrap();
    zip.finish().unwrap();
    assert!(ArtifactVerifier::verify(&out, &keys, &ui).is_err());
}

#[test]
fn test_sign_rejects_newline_filename() {
    let tmp = TempDir::new().unwrap();
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let input = create_test_zip(tmp.path(), "in.zip", &[("a\nb.txt", b"hello")]);
    let out = tmp.path().join("out.zip");
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    let err = ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &out,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap_err();
    assert!(
        format!("{err}").contains("Invalid manifest header"),
        "got {err}"
    );
}

#[test]
fn test_sign_and_verify_long_filename() {
    let tmp = TempDir::new().unwrap();
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let name = format!("dir/{}/file.txt", "x".repeat(200));
    let input = create_test_zip(tmp.path(), "in.zip", &[(name.as_str(), b"hello")]);
    let out = tmp.path().join("out.zip");
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &out,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();
    assert!(ArtifactVerifier::verify(&out, &keys, &ui).unwrap());
}

#[test]
fn test_pin_binds_to_embedded_signer_cert() {
    let tmp = TempDir::new().unwrap();
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let input = create_test_zip(tmp.path(), "in.zip", &[("a.txt", b"hello")]);
    let out = tmp.path().join("out.zip");
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &input,
        &out,
        &keys,
        &nested.digests,
        &nested.nested_files,
        &ui,
    )
    .unwrap();
    assert!(ArtifactVerifier::verify_with_pin(&out, &keys, &ui, Some(DEFAULT_CERT_SHA256)).is_ok());
    let wrong = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";
    assert!(ArtifactVerifier::verify_with_pin(&out, &keys, &ui, Some(wrong)).is_err());
}

#[test]
fn test_verify_accepts_interop_signature_variants() {
    if std::process::Command::new("openssl")
        .arg("version")
        .output()
        .is_err()
    {
        return;
    }
    let tmp = TempDir::new().unwrap();
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    let file_digest = CryptoEngine::compute_sha256(b"hello");
    let section = format!("Name: a.txt\r\nSHA-256-Digest: {file_digest}\r\n\r\n");
    let mf = format!("Manifest-Version: 1.0\r\n\r\n{section}");
    let mf_digest = CryptoEngine::compute_sha256(mf.as_bytes());
    let section_sha256 = CryptoEngine::compute_sha256(section.as_bytes());
    let section_sha384 = CryptoEngine::compute_digest(&ring::digest::SHA384, section.as_bytes());

    let control_sf = format!(
        "Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: {mf_digest}\r\n\r\nName: a.txt\r\nSHA-256-Digest: {section_sha256}\r\n\r\n"
    );
    let mixed_sf = format!(
        "Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: {mf_digest}\r\n\r\nName: a.txt\r\nSHA-384-Digest: {section_sha384}\r\n\r\n"
    );
    let section_only_sf = format!(
        "Signature-Version: 1.0\r\n\r\nName: a.txt\r\nSHA-256-Digest: {section_sha256}\r\n\r\n"
    );

    for (name, sf, sig_name, noattr) in [
        ("control", control_sf.as_str(), "CERT", false),
        ("mixed", mixed_sf.as_str(), "CERT", false),
        ("section", section_only_sf.as_str(), "CERT", false),
        ("noattr", control_sf.as_str(), "CERT", true),
        ("basename", control_sf.as_str(), "RELEASE", false),
    ] {
        let z = openssl_signed_zip(
            tmp.path(),
            name,
            mf.as_bytes(),
            sf.as_bytes(),
            sig_name,
            noattr,
        );
        assert!(
            ArtifactVerifier::verify(&z, &keys, &ui).unwrap(),
            "case {name} failed"
        );
    }
}
