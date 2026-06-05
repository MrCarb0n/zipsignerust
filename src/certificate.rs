// ZipSigner Rust - High-performance, memory-safe cryptographic signing and verification for Android ZIP archives
// Copyright (C) 2025 Tiash H Kabir / @MrCarb0n
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Embedded default development key for ZipSigner Rust.
//!
//! This key is structured in the same shape as the test keys shipped with
//! the Android Open Source Project (AOSP) so that:
//!
//!   * any signature made with it is recognisable on sight (the
//!     certificate subject is `ZipSignerust Dev` and the SHA-256
//!     fingerprint is published in `DEFAULT_CERT_SHA256` below),
//!   * the same on-disk layout (PEM private key, PEM certificate) is used
//!     as production keys, so swapping in a real key is a drop-in change,
//!   * downstreams that pin against the AOSP test key fingerprint can
//!     reject a default-keyed signature with a single constant comparison.
//!
//! **Do not** use this key to sign production artifacts. The private key
//! ships in the binary; anyone with the binary can forge a signature. Pass
//! `--private-key` / `--public-key` to supply your own key.

/// Default certificate subject. Matches the DN layout used by the AOSP
/// `testkey.x509.pem` (CN, OU, O, L, ST, C, EMAILADDRESS).
pub const DEFAULT_SUBJECT: &str =
    "CN=ZipSignerust Dev, OU=Development, O=Open Source, L=Internet, \
     ST=World, C=XX, EMAILADDRESS=dev@zipsignerust.local";

/// SHA-256 fingerprint of `PUBLIC_KEY`, hex-encoded with `:` separators
/// (RFC 7469-style). Computed from the PEM below; treat this constant as
/// a build-time assertion target — if the cert changes, this string and
/// the test in `tests/integration.rs` must move together.
pub const DEFAULT_CERT_SHA256: &str =
    "E3:06:0F:69:4C:10:0E:7E:CB:F3:4F:CE:7B:16:82:5A:FF:A3:E7:9E:50:80:75:31:DA:97:54:6A:F3:63:11:C8";

/// RSA key size in bits. Matches AOSP `testkey` (2048).
pub const DEFAULT_KEY_BITS: u32 = 2048;

/// Default certificate validity window, expressed in whole days from the
/// `notBefore` field. Mirrors AOSP's `~1000 years` convention so
/// reproducible builds keep a stable signature payload.
pub const DEFAULT_VALIDITY_DAYS: u32 = 365_250;

/// Default key purpose. Free-form; surfaced at runtime via the loud
/// warning printed by `KeyChain::load_private_key`.
pub const DEFAULT_KEY_PURPOSE: &str = "development only — DO NOT ship";

// ----------------------------------------------------------------------------
// Key material
// ----------------------------------------------------------------------------

/// Default RSA private key in PKCS#8 PEM form. Loaded when the user does
/// not pass `--private-key`. Generation procedure: see `key.sh` (which can
/// also export a freshly-generated key to this file).
pub const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDgEamm6vrLbsYD
048sqQsdr4xo2LIUiED88OG7jAQQk6IzNWlNUtV1df33X4sMVyNZZjYHMaz7SVN3
uMr9OSjwuq3aFPE26a652D3z8DzFX8d8ShtvScEYHNyFpmBVjYlH4GfzFkTipqVK
AMfNH3tYrTfgk57GyGBx8aqRkW/bBb45LWkHQXX9IuBSooRsH+bfxcZe0lqG1yp2
GHeIA+THvf8US1vPkYihAi4WDFLLZp8tPIgG4WRkufR+e2GXP4q96WAYBB5XFbkC
GHspzNhJ5cc2FgZ3lvMb8UyeVb3qD/dG6+XPsuT+N4wPX1O60fOMEWOMdJeofM6q
VUJEln9ZAgMBAAECggEAQq6O9flFFKiNLlNV7v0JrVZyaztd18Vqzbuj+evjw8kj
wqiZA2Vs2A16vJUG7O+7ud20o3RxncDHIcBxTGWn3Og5V8bWuDhYAr+rRD7Q3w4v
cDofqwFggRwJto56act6uNS8KrgMXQUp+Hl9/Hnre8rk76UO4ep85Tv9vl9xUdT3
iBL/gxqPDYqctsyS3+te26RzJDHhLcs8rii1kS2hh957DIzsb31Q+oHCp9HwgWu9
UZhE9/YrMioRB/RZUVD6opbNxaI26GyGaI1AVanOUAZPI8c5dYHEQX61vYqJT6VO
xk2iYEJEu/SdYP267jFz0ydqMjlpmNMSrilEb19d7wKBgQD5pZ0fIBVTDG2pJmLC
xAUQSBumIGhaa4hhtY8R0feMUQlh8J6jkcNNTS4dmJku3byMA1Rcu1XgBGW87thQ
/9CB5yO4MuO+PNaV3HCONWWQgolQFBx9ZoMgaFB6kTiwVg7eVIYFTjYuD4UDKxje
+YYZaL8v3kW5mrunCTiJfyb2GwKBgQDlxWpLdrIx/opUe+mhAZZL3XvErrtPZcxM
6uo69ISieUqJ0VR86Dwg2t0tnYB40KjZ28EjecJhjjuyBLbtXbwzuF+Y/c9PQp9k
L0ZtpEMAOAZ7eenEpgHFhRdI5wnP/u61jMdhR0JN/QGt4QMTV7NL82iaZRjPzx9O
c9kwIRpHmwKBgG8GQlxHTnSCwHpLgfyQZJgbGYDGROKBlEOwFRKdyHP0zjFqa4Lf
HnZQbsPmy6lWH7Y8/NXI0qYwDnb52eYb/sTm4LHYoARI1j4LrVrxUFv2Uc71Qr5a
StKs0a3Qy99QRoiGGpxdbicJ6+O+1O7FFehS90P4nBWxROdCaIxtqgwlAoGAEb9L
1IRYgzAL8zaW9w6uUzHKS4jLgvhz7UT/zonwbLQ9o6N9iSBO9KKzDsDpmWtUf29P
3bOb5fkcd0WR84eX786/44tHJfIZaZ2VLQbQ/gVVytfBzKSd4mnDQKhHw78HJRK4
m7TrVCbEqG+G00mk2ar1W2ePoQ14d5DPJ76Gzx0CgYBJVv+u6R9fA2yewYxoCMvK
Y8mzDCD0OXf3JSWrJ2CtmGwQLPi8SngsonCntA4PFCCyAnx1COPb50HRpaMYK1IO
RLhy5/YbWnB0qrk08hhgTonLkaOqv7eLaEhqfmP3TIIpWLqTAZ4jjLq8zEq7EAVd
MidBRO4GgCmey1/ozpUafw==
-----END PRIVATE KEY-----"#;

/// Default X.509 certificate (RSA public key + subject + validity) in
/// PEM form. Loaded when the user does not pass `--public-key`.
pub const PUBLIC_KEY: &str = r#"-----BEGIN CERTIFICATE-----
MIID5DCCAsygAwIBAgIJAMGfmD2HUg9WMA0GCSqGSIb3DQEBCwUAMIGeMSUwIwYJ
KoZIhvcNAQkBFhZkZXZAemlwc2lnbmVydXN0LmxvY2FsMQswCQYDVQQGEwJYWDEO
MAwGA1UECBMFV29ybGQxETAPBgNVBAcTCEludGVybmV0MRQwEgYDVQQKEwtPcGVu
IFNvdXJjZTEUMBIGA1UECxMLRGV2ZWxvcG1lbnQxGTAXBgNVBAMTEFppcFNpZ25l
cnVzdCBEZXYwIBcNOTYxMjIyMDIwMDAwWhgPMjk5NjEyMjkwMjAwMDBaMIGeMSUw
IwYJKoZIhvcNAQkBFhZkZXZAemlwc2lnbmVydXN0LmxvY2FsMQswCQYDVQQGEwJY
WDEOMAwGA1UECBMFV29ybGQxETAPBgNVBAcTCEludGVybmV0MRQwEgYDVQQKEwtP
cGVuIFNvdXJjZTEUMBIGA1UECxMLRGV2ZWxvcG1lbnQxGTAXBgNVBAMTEFppcFNp
Z25lcnVzdCBEZXYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgEamm
6vrLbsYD048sqQsdr4xo2LIUiED88OG7jAQQk6IzNWlNUtV1df33X4sMVyNZZjYH
Maz7SVN3uMr9OSjwuq3aFPE26a652D3z8DzFX8d8ShtvScEYHNyFpmBVjYlH4Gfz
FkTipqVKAMfNH3tYrTfgk57GyGBx8aqRkW/bBb45LWkHQXX9IuBSooRsH+bfxcZe
0lqG1yp2GHeIA+THvf8US1vPkYihAi4WDFLLZp8tPIgG4WRkufR+e2GXP4q96WAY
BB5XFbkCGHspzNhJ5cc2FgZ3lvMb8UyeVb3qD/dG6+XPsuT+N4wPX1O60fOMEWOM
dJeofM6qVUJEln9ZAgMBAAGjITAfMB0GA1UdDgQWBBRVDGGuydQfVN5QnTuBNaU+
O1qItzANBgkqhkiG9w0BAQsFAAOCAQEAXL35+FfxLsUtGcNwP7VtRmGeY7p95Xht
WwVzjJByqS19PbhccXx68m8NrJE2bTxpZSmHL6nCC0zADO9/5morWofac7e6I8an
u3K6mNG8BQEGR/n99YDmAsRrpJz9PMdIR8ZeH+Ip3fudcxlZIHp61Sx87ag0b/by
YwiOyxM6tdiGac9gLtIggW3yoU+3sl83XPw5wbYu3Ibowq3OM3DbPQPekV1lm12k
N5PJllGjqj4zlzVLOOOLSFaTHyrPDVNwvQtqEaKsW/5jXySeFz6NILL6n27teMlR
wvTvb2B2MXy7B+I13s0yFlhAK5kmtzrushVlC5cdl9CVc+6eqy8IAg==
-----END CERTIFICATE-----"#;
