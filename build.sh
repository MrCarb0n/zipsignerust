#!/bin/bash
set -euo pipefail

APP_NAME="zipsignerust"
MIN_SDK="24"

TARGETS=(
    "aarch64-linux-android"
    "x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}:: $1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ Error: $1${NC}"
}

main() {
    echo -e "${GREEN}=== $APP_NAME Multi-Platform Builder ===${NC}"

    check_prerequisites
    detect_ndk

    for target in "${TARGETS[@]}"; do
        build_for_target "$target"
    done

    package_and_verify

    log_success "All builds completed successfully!"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    if ! command -v cargo &> /dev/null; then
        log_error "Rust and Cargo are required but not found in PATH."
        echo "Please install Rust from https://rustup.rs/"
        exit 1
    fi

    if [[ " ${TARGETS[*]} " =~ " x86_64-pc-windows-gnu " ]] && ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        log_error "MinGW-w64 toolchain is required for Windows cross-compilation but not found."
        echo "On Debian/Ubuntu, you can install it with: sudo apt install mingw-w64"
        exit 1
    fi

    log_success "Prerequisites check passed."
}

detect_ndk() {
    if [ -z "${ANDROID_NDK_HOME:-}" ]; then
        log_warn "ANDROID_NDK_HOME is not set. Attempting to locate NDK..."
        
        declare -a POSSIBLE_PATHS=(
            "$HOME/Android/Sdk/ndk"/*
            "$HOME/Library/Android/sdk/ndk"/*
            "/usr/local/lib/android/sdk/ndk"/*
            "/opt/android-sdk/ndk"/*
        )
        
        for path in "${POSSIBLE_PATHS[@]}"; do
            if [ -d "$path" ]; then
                export ANDROID_NDK_HOME="$path"
                log_success "Found NDK at: $ANDROID_NDK_HOME"
                break
            fi
        done
        
        if [ -z "${ANDROID_NDK_HOME:-}" ]; then
            log_error "Could not find Android NDK."
            echo "Please install the NDK and set the ANDROID_NDK_HOME environment variable."
            echo "See: https://developer.android.com/studio/projects/install-ndk"
            exit 1
        fi
    else
        log_success "Using NDK from ANDROID_NDK_HOME: $ANDROID_NDK_HOME"
    fi
}

build_for_target() {
    local target=$1
    log_info "Building for target: $target"

    if ! rustup target list --installed | grep -q "$target"; then
        log_info "Adding Rust target $target..."
        rustup target add "$target"
    fi

    if [[ "$target" == *"linux-android"* ]]; then
        configure_android_env "$target"
    fi

    rm -rf "target/$target/release"
    cargo build --release --target "$target"
    log_success "Build for $target complete."
}

configure_android_env() {
    local android_target=$1
    log_info "Configuring environment for Android ($android_target)..."

    local host_tag=""
    case "$OSTYPE" in
        linux-gnu*) host_tag="linux-x86_64" ;;
        darwin*) host_tag="darwin-x86_64" ;;
        msys*) host_tag="windows-x86_64" ;;
        *) log_error "Unsupported build host OS: $OSTYPE" && exit 1 ;;
    esac

    local toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host_tag/bin"
    local api_level=$MIN_SDK
    local arch_triple="${android_target%%-*}"
    
    local target_for_cc="${android_target//-/_}"
    local target_for_cargo="${target_for_cc^^}"

    export CC_"${target_for_cc}"="$toolchain/${arch_triple}-linux-android${api_level}-clang"
    export CXX_"${target_for_cc}"="$toolchain/${arch_triple}-linux-android${api_level}-clang++"
    export AR_"${target_for_cc}"="$toolchain/llvm-ar"
    export CARGO_TARGET_"${target_for_cargo}"_LINKER="$toolchain/${arch_triple}-linux-android${api_level}-clang"
}

package_and_verify() {
    log_info "Packaging binaries..."
    rm -rf dist
    mkdir -p dist

    local checksum_file="dist/sha256sums.txt"
    printf "" > "$checksum_file"

    for target in "${TARGETS[@]}"; do
        local binary_name="$APP_NAME"
        if [[ "$target" == *"windows"* ]]; then
            binary_name="$APP_NAME.exe"
        fi
        
        local binary_path="target/$target/release/$binary_name"
        local output_name

        case "$target" in
            "aarch64-linux-android") output_name="${APP_NAME}-android-arm64" ;;
            "x86_64-unknown-linux-gnu") output_name="${APP_NAME}-linux-x64" ;;
            "x86_64-pc-windows-gnu") output_name="${APP_NAME}-windows-x64.exe" ;;
            *) output_name="${APP_NAME}-${target}" ;;
        esac
        
        if [ -f "$binary_path" ]; then
            cp "$binary_path" "dist/$output_name"
            log_success "Packaged $output_name"
        else
            log_error "Build artifact not found at '$binary_path'. Build may have failed silently."
            exit 1
        fi

        if command -v sha256sum &> /dev/null; then
            sha256sum "dist/$output_name" >> "$checksum_file"
        elif command -v shasum &> /dev/null; then
            shasum -a 256 "dist/$output_name" >> "$checksum_file"
        else
            log_warn "sha256sum/shasum command not found. Skipping checksum generation."
        fi
    done
    
    echo -e "\n${GREEN}Build Complete!${NC}"
    echo "----------------------------------------"
    ls -lh dist/
    echo "----------------------------------------"
    echo "Binary file types:"
    file dist/*
    if [ -f "$checksum_file" ]; then
        echo "----------------------------------------"
        echo "Checksums:"
        cat "$checksum_file"
    fi
}

main "$@"