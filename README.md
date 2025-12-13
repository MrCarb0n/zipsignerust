<div align="center">

# ZipSignerust

**High-performance, memory-safe cryptographic signing and verification for Android ZIP/APK/JAR packages.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/) [![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/MrCarb0n/zipsignerust/releases) 
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
- **🎨 Enhanced UI:** Beautiful colored output with progress bars and structured formatting for better user experience.
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

## 🛠️ Usage

### Sign an Archive

```bash
# Basic signing (creates output file)
zipsignerust sign input.zip signed-output.zip

# Sign in-place (updates input file, creates .bak backup)
zipsignerust sign --inplace input.zip

# Custom keys
zipsignerust sign input.zip output.zip --private-key key.pem --public-key cert.pem

# Verbose mode with colorful output and progress indicators
zipsignerust -v sign input.zip output.zip

# Pipeline support: read from stdin and write to stdout
cat input.zip | zipsignerust sign - - > signed_output.zip
```

### Example Output

When using verbose mode, ZipSignerust provides colorful, structured output:

```
+-----------------------+
|  ZipSignerust v1.0.0  |
+-----------------------+
[i] Loading keys...

-- SIGNING MODE --
[i] Source: input.zip
[i] Target: output.zip
[i] Computing digests...
[i] Signing artifact...
[v] Timestamp used: 2066-06-06 00:06:06 UTC
[v] mtime set on output: output.zip
[+] Archive successfully signed.

Signing Report:
  Status          Success
  Mode            Standard
  Input           input.zip
  Output          output.zip
  Key Used        ZipSignerust Dev
```

### Verify an Archive

```bash
# Verify signature integrity
zipsignerust verify signed-archive.zip

# Verify with verbose output (shows progress indicators)
zipsignerust -v verify signed-archive.zip

# Verify against specific certificate
zipsignerust verify signed-archive.zip --public-key my-cert.pem
```

### Pipeline Support

ZipSignerust supports Unix-style pipelines for seamless integration in automated workflows:

- Use `-` as input to read from stdin
- Use `-` as output to write to stdout
- Examples:
  - Basic pipeline: `cat input.zip | zipsignerust sign - - > signed.zip`
  - Complex workflow: `zip -v -r -9 -Z bzip2 - * | zipsignerust sign - output.zip`
- Progress indicators and colored output work in pipeline mode too when using verbose flag

## ⚙️ Advanced Options

| Option                | Description                                            |
| :-------------------- | :----------------------------------------------------- |
| `-i`, `--inplace`     | Modify the input file directly (creates `.bak` backup) |
| `-f`, `--overwrite`   | Force overwrite if output file exists                  |
| `-k`, `--private-key` | Path to custom private key (PEM/PK8)                   |
| `-p`, `--public-key`  | Path to custom public key/certificate (PEM)            |
| `-v`, `--verbose`     | Enable verbose logging with progress indicators        |
| `-q`, `--quiet`       | Suppress all output except errors                      |

## 🎨 Enhanced UI Features

ZipSignerust features a modern, colorful terminal interface with:

- **Color-coded output** for different message types (success, warnings, errors, info)
- **Progress bars** for long-running operations (when using `--verbose`)
- **Structured tables** for displaying key-value information
- **Improved banners** and headers for better visual organization
- **Cross-platform color support** (including Windows terminal compatibility)

## 🧩 How It Works

1.  **Manifest Generation:** Creates `META-INF/MANIFEST.MF` with SHA-1 digests of all files.
2.  **Signature File:** Creates `META-INF/CERT.SF` containing digests of the manifest.
3.  **RSA Signature:** Creates `META-INF/CERT.RSA` block containing the signature of the SF file.
4.  **Nested Processing:** If a nested archive is found, it extracts, signs, and re-embeds it before signing the parent.

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">
Made with ❤️ from Bangladesh 🇧🇩
</div>
