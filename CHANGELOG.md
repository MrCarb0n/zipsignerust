# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-06

### Added

- **Core:** Deterministic ZIP/APK/JAR signing engine using Rust.
- **Crypto:** RSA-2048 signing with SHA-256 digests.
- **Features:**
  - Recursive nested archive signing (ZIP inside ZIP).
  - In-place signing with automatic backup (`--inplace`).
  - Signature verification (`verify` command).
  - Configurable keys (custom PEM or embedded fallback).
- **Safety:** Timestamp reproducibility fix (uses certificate creation date).
- **Platform:** Cross-platform support (Linux, Android, Windows).

### Changed

- Complete rewrite in Rust for memory safety and performance.
- Optimized binary size (~1.6MB).
