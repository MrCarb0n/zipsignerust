#!/bin/bash
# Tiash @MrCarb0n Key Generator & PK8 Export Script
# Updated for zipsignerust compatibility
set -euo pipefail

# ------------------------------
# Configuration (edit if needed)
# ------------------------------
ALIASES="MrCarb0n"
DEFAULT_PASS="Key@84274"
VALIDITY=365250
ISSUED_DATE="1996/12/22 22:22:22"

CommonName="Dev"
OrganizationalUnit="Dev"
Organization="Earth Inc."
Email="MrCarb0n@proton.me"
Locality="Dhaka"
State_Province="Dhaka"
Country="BD"

# ------------------------------
# Directories
# ------------------------------
# 1. Main storage (Backups in Home dir)
KEY_DIR="$HOME/KEY_MrCarb0n"
mkdir -p "$KEY_DIR"

# 2. Project storage (For the Rust tool)
PROJECT_CERTS_DIR="./certs"
mkdir -p "$PROJECT_CERTS_DIR"

# Paths
KEY_STORE_PATH="$KEY_DIR/${ALIASES}.keystore"
DEST_KEY_STORE_PATH="$KEY_DIR/${ALIASES}.p12"
TMP_RSA_PATH="$KEY_DIR/tmp_${ALIASES}.rsa.pem"

# Output Files
PRIVATE_RSA="$KEY_DIR/private_${ALIASES}.rsa.pem"
CERT_X509="$KEY_DIR/x509.pem"
PK8_PATH="$KEY_DIR/private_${ALIASES}.pk8"

# ------------------------------
# Utility: check for errors
# ------------------------------
check_error() {
    if [ $? -ne 0 ]; then
        echo "❌ Error: Command failed, aborting."
        exit 1
    fi
}

# ------------------------------
# Generate keystore
# ------------------------------
generate_keystore() {
    echo ":: Generating keystore..."
    if [ -f "${KEY_STORE_PATH}" ]; then
        echo "   Keystore exists, skipping generation."
    else
        keytool -genkeypair -v \
            -keystore "${KEY_STORE_PATH}" \
            -alias "${ALIASES}" \
            -storepass "${PASS}" \
            -keypass "${PASS}" \
            -keyalg RSA \
            -keysize 2048 \
            -sigalg SHA256withRSA \
            -startdate "${ISSUED_DATE}" \
            -validity "${VALIDITY}" \
            -dname "CN=${CommonName}, OU=${OrganizationalUnit}, O=${Organization}, L=${Locality}, ST=${State_Province}, C=${Country}, EMAILADDRESS=${Email}"
        check_error
    fi
}

# ------------------------------
# Convert keystore to PKCS12
# ------------------------------
convert_to_pkcs12() {
    echo ":: Converting keystore to PKCS12..."
    # Suppress error if alias already exists in dest (for re-runs)
    keytool -importkeystore \
        -srckeystore "${KEY_STORE_PATH}" \
        -destkeystore "${DEST_KEY_STORE_PATH}" \
        -srcstoretype JKS \
        -deststoretype PKCS12 \
        -deststorepass "${PASS}" \
        -srcstorepass "${PASS}" \
        -destkeypass "${PASS}" \
        -noprompt 2>/dev/null || true
    check_error
}

# ------------------------------
# Convert PKCS12 to PEM
# ------------------------------
convert_to_pem() {
    echo ":: Converting PKCS12 to PEM..."
    openssl pkcs12 -nodes \
        -in "${DEST_KEY_STORE_PATH}" \
        -out "${TMP_RSA_PATH}" \
        -password pass:"${PASS}"
    check_error
}

# ------------------------------
# Extract keys & Deploy to Project
# ------------------------------
extract_and_deploy() {
    echo ":: Extracting private key and certificate..."
    
    # 1. Extract Private Key
    sed -n "/BEGIN PRIVATE KEY/,/END PRIVATE KEY/p" "${TMP_RSA_PATH}" > "${PRIVATE_RSA}"
    check_error
    
    # 2. Extract Certificate
    sed -n "/BEGIN CERTIFICATE/,/END CERTIFICATE/p" "${TMP_RSA_PATH}" > "${CERT_X509}"
    check_error

    echo ":: Deploying keys to project..."
    # Copy to ./certs/ with the names expected by src/main.rs
    cp "${PRIVATE_RSA}" "${PROJECT_CERTS_DIR}/private_key.pem"
    echo "   -> Created ${PROJECT_CERTS_DIR}/private_key.pem"
    
    cp "${CERT_X509}" "${PROJECT_CERTS_DIR}/public_key.pem"
    echo "   -> Created ${PROJECT_CERTS_DIR}/public_key.pem"
}

# ------------------------------
# Convert private key to PK8 (Legacy)
# ------------------------------
convert_to_pk8() {
    echo ":: Converting private key to PK8..."
    openssl pkcs8 -topk8 \
        -outform DER \
        -in "${PRIVATE_RSA}" \
        -inform PEM \
        -out "${PK8_PATH}" \
        -nocrypt
    check_error
    echo "   PK8 file created: ${PK8_PATH}"
}

# ------------------------------
# Optional: create encrypted ZIP
# ------------------------------
create_encrypted_zip() {
    echo ":: Creating encrypted ZIP backup..."
    ZIP_FILE="$KEY_DIR/KEY_${ALIASES}.zip"
    
    # Check if zip exists, skip prompt if running non-interactively, or ask
    if [ -f "$ZIP_FILE" ]; then
        echo "   Backup zip exists, overwriting..."
    fi

    # FIX: use -j to store files at root of ZIP
    zip -j -Z deflate -P "${PASS}" "$ZIP_FILE" \
        "${KEY_STORE_PATH}" \
        "${DEST_KEY_STORE_PATH}" \
        "${TMP_RSA_PATH}" \
        "${PRIVATE_RSA}" \
        "${CERT_X509}" \
        "${PK8_PATH}"
    check_error
    echo "   Encrypted ZIP created: $ZIP_FILE"
}

# ------------------------------
# Prompt password
# ------------------------------
read -s -p "Enter password (or press Enter to use default): " PASS
echo
[ -z "$PASS" ] && PASS="$DEFAULT_PASS"

# ------------------------------
# Main execution
# ------------------------------
echo "---------------------------------------"
echo "Starting Tiash @MrCarb0n Key Generator..."
echo "---------------------------------------"

generate_keystore
convert_to_pkcs12
convert_to_pem
extract_and_deploy
convert_to_pk8
create_encrypted_zip

# Cleanup temporary PEM/keystore files (optional)
rm -f "${DEST_KEY_STORE_PATH}" "${TMP_RSA_PATH}"
echo ":: Cleanup complete."

echo "---------------------------------------"
echo "✅ Setup Complete!"
echo "   - Project Keys: ${PROJECT_CERTS_DIR}/"
echo "   - Backup Keys:  ${KEY_DIR}/"
echo "   - Issued Date:  ${ISSUED_DATE}"
echo "---------------------------------------"