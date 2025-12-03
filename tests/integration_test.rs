extern crate zipsignerust;

use std::path::PathBuf;
use zipsignerust::{build_command, run};

#[test]
fn test_sign_and_verify() {
    let input_path = PathBuf::from("tests/test-assets/test.zip");
    let output_path = PathBuf::from("tests/test-assets/test_signed.zip");

    // Sign the zip file
    let sign_matches = build_command().get_matches_from(vec![
        "zipsignerust",
        input_path.to_str().unwrap(),
        output_path.to_str().unwrap(),
    ]);
    let sign_result = run(&sign_matches);
    assert!(sign_result.is_ok());

    // Verify the signed zip file
    let verify_matches =
        build_command().get_matches_from(vec!["zipsignerust", "--verify", output_path.to_str().unwrap()]);
    let verify_result = run(&verify_matches);
    assert!(verify_result.is_ok());

    // Clean up the signed zip file
    std::fs::remove_file(output_path).unwrap();
}
