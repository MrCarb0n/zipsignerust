<div align="center">

# ZipSignerust

**High-performance, memory-safe cryptographic signing and verification for Android ZIP archives.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/) [![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/MrCarb0n/zipsignerust/releases)
</div>

---

**ZipSignerust** is a deterministic, high-performance tool written in Rust to sign and verify Android ZIP archives. It ensures reproducible builds by using certificate creation timestamps and supports recursive signing of nested ZIP archives.

## 🚀 Key Features

- **⚡ High Performance:** Written in pure Rust for maximum speed and memory safety.
- **🔒 Deterministic timestamps:** Uses the certificate's creation date for all ZIP entries (reproducible builds).
- **🔍 Recursive Signing:** Automatically detects and signs nested `.zip` files inside archives.
- **🛡️ Secure:** Uses industry-standard cryptography (RSA, SHA-1/SHA-256) for signature generation and verification.
- **💾 In-Place Signing:** Smart `--inplace` mode with automatic backup for efficient workflow.
- **🔑 Flexible Keys:** Use your own PK8/PEM keys or fallback to embedded developer keys for quick testing.
- **✅ Comprehensive Verification:** Verify the integrity and authenticity of existing archives with detailed validation.
- **🔌 Pipeline Support:** Full stdin/stdout support for integration in automated workflows.

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

## 🚀 Quick Start

```bash
# Sign an archive
zipsignerust sign input.zip signed-output.zip

# Verify an archive
zipsignerust verify signed-archive.zip
```

## 📚 Documentation

- [Usage Guide](docs/usage.md) — signing, verification, pipelines, advanced options
- [Internals](docs/internals.md) — how signing works and what verification checks

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---

<div align="center">
Made with ❤️ from Bangladesh 🇧🇩
</div>
