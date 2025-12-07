use std::{env, fs, io::Write, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let certs_dir = PathBuf::from("certs");
    let priv_path = certs_dir.join("private_key.pem");
    let pub_path = certs_dir.join("public_cert.pem");
    println!("cargo:rustc-check-cfg=cfg(has_merged_keys)");
    println!("cargo:rerun-if-changed={}", priv_path.display());
    println!("cargo:rerun-if-changed={}", pub_path.display());
    if priv_path.exists() && pub_path.exists() {
        let priv_contents = fs::read_to_string(&priv_path).unwrap();
        let pub_contents = fs::read_to_string(&pub_path).unwrap();
        let mut out_file = fs::File::create(out_dir.join("merged_keys.rs")).unwrap();
        write!(
            out_file,
            "pub const PRIVATE_KEY: &str = r#\"{}\"#;\npub const PUBLIC_KEY: &str = r#\"{}\"#;\n",
            priv_contents,
            pub_contents
        )
        .unwrap();
        println!("cargo:rustc-cfg=has_merged_keys");
    }
}
