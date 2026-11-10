# Usage Guide

## Sign an Archive

```bash
# Basic signing (creates output file)
zipsignerust sign input.zip signed-output.zip

# Sign in-place (updates input file, keeps a unique timestamped .bak backup)
zipsignerust sign --inplace input.zip

# Custom keys (the two options are required together and must match)
zipsignerust sign input.zip output.zip --private-key key.pem --public-key cert.pem

# Verbose mode with colorful output and progress indicators
zipsignerust -v sign input.zip output.zip

# Pipeline support: read from stdin and write to stdout
cat input.zip | zipsignerust sign - - > signed_output.zip
```

`sign` rejects using the same file as input and output (except `--inplace`) and refuses manifest-unsafe entry names such as names containing newlines. Duplicate entry names are rejected. Backup files are never overwritten if a same-second backup already exists.

### Example Output

When using verbose mode, ZipSignerust provides colorful, structured output:

```
+-----------------------+
|  ZipSignerust v2.0.0  |
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

## Verify an Archive

```bash
# Verify signature integrity
zipsignerust verify signed-archive.zip

# Verify with verbose output (shows detailed validation)
zipsignerust -v verify signed-archive.zip

# Verify the embedded signer certificate fingerprint (colons optional, case-insensitive)
zipsignerust verify signed-archive.zip --pin AA:BB:CC:…
```

## Pipeline Support

ZipSignerust supports Unix-style pipelines for seamless integration in automated workflows:

- Use `-` as input to read from stdin
- Use `-` as output to write to stdout
- Examples:
  - Basic pipeline: `cat input.zip | zipsignerust sign - - > signed.zip`
  - Complex workflow: `zip -v -r -9 -Z bzip2 - * | zipsignerust sign - output.zip`
- Progress indicators and colored output work in pipeline mode too when using verbose flag

## Advanced Options

| Option                | Description                                            |
| :-------------------- | :----------------------------------------------------- |
| `-i`, `--inplace`     | Modify the input file directly (keeps a timestamped `.bak` backup) |
| `-f`, `--overwrite`   | Force overwrite if output file exists                  |
| `-k`, `--private-key` | Path to custom private key (PEM/PK8)                   |
| `-p`, `--public-key`  | Path to custom public key/certificate (PEM)            |
| `-P`, `--pin`         | Expected signer cert SHA-256 fingerprint (`verify`)    |
| `-v`, `--verbose`     | Enable verbose logging with progress indicators        |
| `-q`, `--quiet`       | Suppress all output except errors                      |
| `-V`, `--version`     | Print version information                              |

## UI Features

- **Color-coded output** for different message types (success, warnings, errors, info)
- **Progress bars** for long-running operations (when using `--verbose`)
- **Structured tables** for displaying key-value information
- **Cross-platform color support** (including Windows terminal compatibility)
