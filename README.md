
<div align="center">

# ZipSignerust

**High-performance, memory-safe cryptographic signing and verification for Android ZIP/APK/JAR packages.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/MrCarb0n/zipsignerust/releases)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

</div>

---

**ZipSignerust** is a deterministic, high-performance tool written in Rust to sign and verify Android ZIP, APK, and JAR archives. It ensures reproducible builds by using certificate creation timestamps and supports recursive signing of nested archives.

## 🚀 Key Features

- **⚡ High Performance:** Written in pure Rust for maximum speed and memory safety.
- **🔒 Deterministic timestamps:** Uses the certificate's creation date for all ZIP entries (reproducible builds).
- **📂 Recursive Signing:** Automatically detects and signs nested `.zip`, `.jar`, and `.apk` files inside archives.
- **🛡️ Secure:** Uses RSA-2048 with SHA-256 digests (standard Android safety).
- **💾 In-Place Signing:** Smart `--inplace` mode with automatic backup for efficient workflow.
- **🔑 Flexible Keys:** Use your own PK8/PEM keys or fallback to embedded developer keys for quick testing.
- **✅ Verification:** Verify the integrity and authenticity of existing archives.

## 📦 Installation

### From Binaries

Download the pre-built binary for your platform from the [Releases](https://github.com/MrCarb0n/zipsignerust/releases) page.

### From Source

```bash
# Clone the repository
git clone https://github.com/MrCarb0n/zipsignerust.git
cd zipsignerust

# Build with cargo
cargo build --release

# Binary will be at target/release/zipsignerust
```

## 🛠️ Usage

### Sign an Archive

```bash
# Basic signing (creates output file)
zipsignerust sign input.zip signed-output.zip

# Sign in-place (updates input file, creates .bak backup)
zipsignerust sign --inplace input.zip

# Custom keys
zipsignerust sign input.zip output.zip --private-key key.pem --public-key cert.pem
```

### Verify an Archive

```bash
# Verify signature integrity
zipsignerust verify signed-archive.zip

# Verify against specific certificate
zipsignerust verify signed-archive.zip --public-key my-cert.pem
```

## ⚙️ Advanced Options

| Option | Description |
| :--- | :--- |
| `-i`, `--inplace` | Modify the input file directly (creates `.bak` backup) |
| `-f`, `--overwrite` | Force overwrite if output file exists |
| `-k`, `--private-key` | Path to custom private key (PEM/PK8) |
| `-p`, `--public-key` | Path to custom public key/certificate (PEM) |

## 🧩 How It Works

1. **Manifest Generation:** Creates `META-INF/MANIFEST.MF` with SHA-1 digests of all files.
2. **Signature File:** Creates `META-INF/CERT.SF` containing digests of the manifest.
3. **RSA Signature:** specific `META-INF/CERT.RSA` block containing the signature of the SF file.
4. **Nested Processing:** If a nested archive is found, it extracts, signs, and re-embeds it before signing the parent.

## 🤝 Contributing

Contributions are welcome! Please check [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---
<div align="center">
Made with ❤️ by <a href="https://github.com/MrCarb0n">Tiash / @MrCarb0n</a>
</div>
