# Internals

## How Signing Works

1.  **Digest Computation:** Computes SHA-256 digests for all files in the archive, excluding signature files.
2.  **Manifest Generation:** Creates `META-INF/MANIFEST.MF` with file paths and their SHA-256 digests (wrapped per JAR rules; invalid header characters rejected).
3.  **Signature File:** Creates `META-INF/CERT.SF` containing digests of the manifest entries.
4.  **RSA Signature:** Creates `META-INF/CERT.RSA` with the RSA signature of the SF file.
5.  **Nested Processing:** Recursively processes nested ZIP files within the archive, ensuring they're signed before the parent archive.
6.  **Safe Output:** Writes to a temporary file and rejects same input/output paths to avoid data loss; `--inplace` keeps a unique, non-overwritten backup.
7.  **Integrity Validation:** Rejects duplicate entry names and performs CRC checks to ensure file integrity.
8.  **Timestamp Setting:** Applies consistent timestamps for reproducible builds.

## What Verification Checks

- **Signature Validity:** Validates the PKCS7/CMS RSA signature (SHA-1/256/384/512 digest algorithms) against the embedded signer certificate
- **Manifest Integrity:** Ensures manifest hashes match actual files (whole-manifest digest when present, and per-entry digests)
- **Entry Consistency:** Verifies all files have corresponding entries and rejects duplicate archive entry names
- **Digest Verification:** Checks SHA-1/256/384/512 manifest/SF digests (SHA-256 written; common interoperable variants accepted)
- **Structure Validation:** Ensures proper JAR signing format
- **Integrity Check:** Performs CRC verification on all entries and rejects malformed/deeply nested signature structures
- **`--pin`:** When supplied, requires the embedded signer certificate SHA-256 fingerprint to match the expected value (constant-time comparison)
