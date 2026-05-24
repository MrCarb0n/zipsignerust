use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;
use zipsignerust::{
    crypto::CryptoEngine,
    error::SignerError,
    keys::KeyChain,
    processor::ArtifactProcessor,
    ui::Ui,
    verification::ArtifactVerifier,
};

fn create_test_zip(dir: &Path, name: &str, files: &[(&str, &[u8])]) -> std::path::PathBuf {
    let path = dir.join(name);
    let file = std::fs::File::create(&path).unwrap();
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::<()>::default()
        .compression_method(CompressionMethod::Stored);

    for (name, content) in files {
        zip.start_file(name, opts).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap();
    path
}

fn silent_ui() -> Ui {
    Ui::new(false, false, false, true, false)
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
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &key_chain, &ui).unwrap();

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
        &input, &signed, &keys, &nested.digests, &nested.nested_files, &ui,
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
                msg.contains("No RSA Signature file found"),
                "expected 'No RSA Signature file found' error, got: {}",
                msg
            );
        }
        other => panic!("expected Validation error for unsigned zip, got: {:?}", other),
    }
}

#[test]
fn test_sign_and_verify_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let input = create_test_zip(tmp.path(), "input.zip", &[
        ("a.txt", b"hello"),
        ("b.txt", b"world"),
    ]);
    let signed = tmp.path().join("signed.zip");
    let ui = silent_ui();

    let keys = KeyChain::new(None, None, &ui).unwrap();
    let nested = ArtifactProcessor::compute_digests_prepare_nested(&input, &keys, &ui).unwrap();
    ArtifactProcessor::write_signed_zip_with_sources(
        &input, &signed, &keys, &nested.digests, &nested.nested_files, &ui,
    ).unwrap();

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
        &input, &signed, &keys, &nested.digests, &nested.nested_files, &ui,
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
    assert_eq!(
        digest1, digest2,
        "SHA1 must be deterministic"
    );
}

#[test]
fn test_key_chain_default_keys() {
    let ui = silent_ui();
    let keys = KeyChain::new(None, None, &ui).unwrap();
    assert!(
        keys.private_key.is_some(),
        "default private key must load"
    );
    assert!(
        keys.public_key.is_some(),
        "default public key must load"
    );
    assert!(
        keys.cert_der.is_some(),
        "default certificate must load"
    );
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
        &input, &signed, &keys, &nested.digests, &nested.nested_files, &ui,
    )
    .unwrap();

    // Corrupt a byte in the signature data (middle of file)
    let mut bytes = std::fs::read(&signed).unwrap();
    let idx = bytes.len() / 2;
    bytes[idx] ^= 0xFF;
    std::fs::write(&signed, &bytes).unwrap();

    let verify_keys = KeyChain::new(None, None, &ui).unwrap();
    let result = ArtifactVerifier::verify(&signed, &verify_keys, &ui);
    assert!(result.is_err(), "corrupted archive must fail verification");
}
