#!/bin/bash
set -e

# Configuration
APP_NAME="zipsignerust"
ANDROID_TARGET="aarch64-linux-android"
LINUX_TARGET="x86_64-unknown-linux-gnu"
MIN_SDK="24" # Android 7.0+

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== $APP_NAME Multi-Platform Builder ===${NC}"

# 1. Check for Android NDK
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo -e "${YELLOW}Warning: ANDROID_NDK_HOME is not set.${NC}"
    echo "Attempting to locate NDK in standard locations..."
    
    # Common NDK locations
    POSSIBLE_PATHS=(
        "$HOME/Android/Sdk/ndk/"*
        "/usr/local/lib/android/sdk/ndk/"*
        "/opt/android-sdk/ndk/"*
    )
    
    for path in "${POSSIBLE_PATHS[@]}"; do
        # Expand glob
        expanded_paths=($path)
        if [ -d "${expanded_paths[0]}" ]; then
            export ANDROID_NDK_HOME="${expanded_paths[0]}"
            echo -e "Found NDK at: ${GREEN}$ANDROID_NDK_HOME${NC}"
            break
        fi
    done
    
    if [ -z "$ANDROID_NDK_HOME" ]; then
        echo -e "${RED}Error: Could not find Android NDK.${NC}"
        echo "Please install the NDK and set ANDROID_NDK_HOME."
        echo "Example: export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/25.2.9519653"
        exit 1
    fi
fi

# 2. Determine Host OS for NDK Toolchain
HOST_TAG=""
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    HOST_TAG="linux-x86_64"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    HOST_TAG="darwin-x86_64"
else
    echo -e "${RED}Error: Unsupported build host OS: $OSTYPE${NC}"
    exit 1
fi

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"

# 3. Setup Android Environment Variables
echo -e "${GREEN}Configuring environment for Android ($ANDROID_TARGET)...${NC}"

# Add Rust target if missing
rustup target add $ANDROID_TARGET

# Set compilers for C/C++ (Needed for OpenSSL vendored build)
export CC_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android${MIN_SDK}-clang"
export CXX_aarch64_linux_android="$TOOLCHAIN/aarch64-linux-android${MIN_SDK}-clang++"
export AR_aarch64_linux_android="$TOOLCHAIN/llvm-ar"

# Tell Cargo which linker to use
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"

# 4. Build for Android
echo -e "${GREEN}Building for Android (ARM64)...${NC}"
cargo build --release --target $ANDROID_TARGET

# 5. Build for Linux
echo -e "${GREEN}Building for Linux (x64)...${NC}"
cargo build --release --target $LINUX_TARGET

# 6. Organize Output
echo -e "${GREEN}Packaging binaries...${NC}"
mkdir -p dist
cp "target/$ANDROID_TARGET/release/$APP_NAME" "dist/${APP_NAME}-android-arm64"
cp "target/$LINUX_TARGET/release/$APP_NAME" "dist/${APP_NAME}-linux-x64"

# 7. Verify
echo -e "\n${GREEN}Build Complete!${NC}"
echo "----------------------------------------"
ls -lh dist/
echo "----------------------------------------"
echo "Android binary type:"
file "dist/${APP_NAME}-android-arm64"