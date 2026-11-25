# Internals

## Signing

Nested ZIPs are signed before the parent archive. The signer writes SHA-256
file digests to `META-INF/MANIFEST.MF`, manifest digests to `META-INF/CERT.SF`,
and the RSA signature block to `META-INF/CERT.RSA`. ZIP entry timestamps come
from the certificate's `notBefore` date.

The signer rejects duplicate names and checks the staged archive's CRCs before
publishing it.

## Verification

The verifier selects the embedded signer certificate by issuer and serial
number, checks it against the expected public key or certificate pin, and
verifies the RSA signature. Signed attributes must include the `.SF` digest.
Without signed attributes, the signature covers the `.SF` file directly.

The verifier checks manifest and payload digests and rejects duplicate archive
entries. It accepts SHA-1, SHA-256, SHA-384, and SHA-512 digests for verification.
