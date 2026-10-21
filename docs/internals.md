# Internals

## How Signing Works

1.  **Digest Computation:** Computes SHA-256 digests for all files in the archive, excluding signature files.
2.  **Manifest Generation:** Creates `META-INF/MANIFEST.MF` with file paths and their SHA-256 digests.
3.  **Signature File:** Creates `META-INF/CERT.SF` containing digests of the manifest entries.
4.  **RSA Signature:** Creates `META-INF/CERT.RSA` with the RSA signature of the SF file.
5.  **Nested Processing:** Recursively processes nested ZIP files within the archive, ensuring they're signed before the parent archive.
6.  **Integrity Validation:** Performs CRC checks on all entries to ensure file integrity.
7.  **Timestamp Setting:** Applies consistent timestamps for reproducible builds.

## What Verification Checks

- **Signature Validity:** Validates the PKCS7/RSA signature (SHA-1/256/384/512 digest algorithms) against the certificate
- **Manifest Integrity:** Ensures manifest hashes match actual files
- **Entry Consistency:** Verifies all files have corresponding entries
- **Digest Verification:** Checks SHA-1/256/384/512 manifest digests (SHA-256 written, all four accepted on read)
- **Structure Validation:** Ensures proper JAR signing format
- **Integrity Check:** Performs CRC verification on all entries
