<div align="center">

# ZipSignerust

**High-performance, memory-safe cryptographic signing and verification for Android ZIP archives.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/) [![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/MrCarb0n/zipsignerust/releases)
</div>

---

**ZipSignerust** is a deterministic, high-performance tool written in Rust to sign and verify Android ZIP archives. It ensures reproducible builds by using certificate creation timestamps and supports recursive signing of nested ZIP archives.

## 🚀 Key Features

- **⚡ High Performance:** Written in pure Rust for maximum speed and memory safety.
- **🔒 Deterministic timestamps:** Uses the certificate's creation date for all ZIP entries (reproducible builds).
- **🔍 Recursive Signing:** Automatically detects and signs nested `.zip` files inside archives.
- **🛡️ Secure:** Uses industry-standard cryptography (RSA, SHA-256; SHA-1/384/512 accepted on read) for signature generation and verification.
- **💾 In-Place Signing:** Smart `--inplace` mode with a timestamped `.bak` backup kept for safety.
- **🔑 Flexible Keys:** Use your own PK8/PEM keys or fallback to embedded developer keys for quick testing.
- **✅ Signer Verification:** Check archive integrity against a trusted public key or a pinned signer certificate.
- **🔌 Pipeline Support:** Full stdin/stdout support for integration in automated workflows.

## 📦 Installation

### From Binaries

Download the pre-built binary for your platform from the [Releases](https://github.com/MrCarb0n/zipsignerust/releases) page.

### From Source

The project declares Rust 1.88 or newer. Build from the repository with its lockfile:

```bash
# Clone the repository
git clone https://github.com/MrCarb0n/zipsignerust.git
cd zipsignerust

# Build or install
cargo build --locked --release
cargo install --locked --path .

# The build output is target/release/zipsignerust (zipsignerust.exe on Windows).
```

Linux and Android ARM64/ARMv7 have been tested. Windows and macOS have not
been tested for this revision. See [Building and Testing](docs/building.md)
for the Android cross-build and the test coverage.

## 🚀 Quick Start

```bash
# Sign an archive
zipsignerust sign input.zip signed-output.zip

# Verify the output against the built-in development key
zipsignerust verify signed-output.zip
```

The built-in development key is public. Use your own key and a trusted
certificate or pin for production workflows.

## 📚 Documentation

- [Usage Guide](docs/usage.md) — signing, verification, pipelines, advanced options
- [Building and Testing](docs/building.md) — locked builds, Android targets, and test coverage
- [Internals](docs/internals.md) — how signing works and what verification checks

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---

<div align="center">
Made with ❤️ from Bangladesh 🇧🇩
</div>
