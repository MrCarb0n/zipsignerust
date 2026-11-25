# Building and Testing

From the repository root, use the checked-in `Cargo.lock`:

```sh
cargo build --locked --release
cargo test --locked --all-targets -- --test-threads=1
cargo test --locked --release --all-targets -- --test-threads=1
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

Run the full host suite with `python3` and `openssl` on `PATH` for fixture
generation and interoperability checks.

## Cross-build for Android from Linux

Set `ANDROID_NDK_HOME` to the installed NDK directory. The commands below
use the Linux x86-64 toolchain and target Android API 21:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi
ndk="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk/aarch64-linux-android21-clang"
export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
export AR_aarch64_linux_android="$ndk/llvm-ar"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$ndk/armv7a-linux-androideabi21-clang"
export CC_armv7_linux_androideabi="$CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER"
export AR_armv7_linux_androideabi="$ndk/llvm-ar"

for target in aarch64-linux-android armv7-linux-androideabi; do
    cargo build --locked --release --target "$target"
    cargo test --locked --target "$target" --no-run
done
```

The release binaries are in `target/<target>/release/zipsignerust`.
`--no-run` compiles and links the test binaries; it does not run them on Android.

## Verified platforms

Results for `f0bebec`:

| Platform | Result |
| --- | --- |
| Linux x86-64 | 94 tests passed in debug and release. Release CLI smoke checks passed. |
| Android ARM64 and ARMv7 | Both builds linked with NDK 27.2 at API 21. On a Redmi Note 4 (API 35), each passed 64 unit and 24 integration tests, plus release CLI smoke checks. |
| Windows x86-64, macOS x86-64 and ARM64 | Native release tests and CLI signing and verification passed in [GitHub Actions](https://github.com/MrCarb0n/zipsignerust/actions/runs/45698912026). |

Six Android integration tests per ABI were skipped because they depend on
host paths or tools. On-device CLI checks covered signing and verification,
output and backup protection, stdin/stdout, and all three legacy/JDK fixtures.
Android recovery, Android API 21 runtime compatibility, and the declared
Rust 1.88 minimum were not tested.
