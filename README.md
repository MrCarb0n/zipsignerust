<div align="center">

# ZipSignerust

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE) [![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/) [![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/MrCarb0n/zipsignerust/releases/tag/latest)

</div>

Sign and verify Android ZIP archives with RSA JAR signatures. ZipSignerust signs
nested ZIPs recursively and supports in-place signing and stdin/stdout.

## Installation

### Binaries

The [rolling release](https://github.com/MrCarb0n/zipsignerust/releases/tag/latest)
has binaries for Linux, Windows, macOS, and Android.

### From source

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

## Quick start

```bash
# Sign an archive
zipsignerust sign input.zip signed-output.zip

# Verify the output against the built-in development key
zipsignerust verify signed-output.zip
```

The built-in development key is public. Use your own key and a trusted
certificate or pin for production workflows.

## Documentation

- [Usage](docs/usage.md)
- [Build and test](docs/building.md)
- [Signature format and verification](docs/internals.md)

## License

[GPL-3.0-or-later](LICENSE).
