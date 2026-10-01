#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?}"; : "${RUNNER_TEMP:?}"
fail() { echo "$*" >&2; exit 1; }
common=(--target alpha --target mullvadbrowser-windows-x86_64 --target pgo-generate)
cd "$UPSTREAM"
rust_filename="$(./rbm/rbm showconf rust filename "${common[@]}")"
official_filename="$(./rbm/rbm showconf rust filename --target alpha --target mullvadbrowser-windows-x86_64)"
[[ "$rust_filename" != "$official_filename" && "$rust_filename" == *-profiler* ]] || fail 'PGO Rust did not resolve to its distinct profiler identity'
mingw_filename="$(./rbm/rbm showconf mingw-w64-clang filename "${common[@]}")"
# Select the filenames evaluated by RBM, never the first file in an output tree.
[[ "$rust_filename" != */* && -n "$rust_filename" && "$mingw_filename" != */* && -n "$mingw_filename" ]] || fail 'RBM returned an invalid toolchain filename'
rust_archive="$PWD/out/rust/$rust_filename"
mingw_archive="$PWD/out/mingw-w64-clang/$mingw_filename"
[[ -s "$rust_archive" ]] || fail "selected PGO Rust input is missing: $rust_filename"
[[ -s "$mingw_archive" ]] || fail "selected MinGW input is missing: $mingw_filename"
echo "Exact PGO Rust RBM input: $rust_archive (sha256=$(sha256sum "$rust_archive" | cut -d' ' -f1), size=$(stat -c%s "$rust_archive"))"
echo "Exact MinGW RBM input: $mingw_archive (sha256=$(sha256sum "$mingw_archive" | cut -d' ' -f1), size=$(stat -c%s "$mingw_archive"))"
tools="$RUNNER_TEMP/pgo-rust-preflight-tools"; rm -rf "$tools"; mkdir -p "$tools/rust" "$tools/mingw"
tar -xaf "$rust_archive" -C "$tools/rust"
tar -xaf "$mingw_archive" -C "$tools/mingw"
rust_sysroot="$(realpath -e "$tools/rust/rust")"
mingw_root="$(realpath -e "$tools/mingw/mingw-w64-clang")"
[[ "$rust_sysroot" == "$(realpath -e "$tools/rust")/rust" ]] || fail 'Rust sysroot escapes the restored PGO artifact'
[[ "$mingw_root" == "$(realpath -e "$tools/mingw")/mingw-w64-clang" ]] || fail 'MinGW root escapes the restored artifact'
rustc="$rust_sysroot/bin/rustc"
linker="$mingw_root/bin/x86_64-w64-mingw32-clang"
mingw_sysroot="$mingw_root/x86_64-w64-mingw32"
# Official tool archives can contain executable symlinks. Check their destination
# for containment, but invoke the named entry point (wrappers depend on $0).
for entry in "$rustc" "$linker"; do
  [[ -f "$entry" && -x "$entry" ]] || fail "missing executable toolchain entry point: $entry"
done
[[ "$(realpath -e "$rustc")" == "$rust_sysroot/"* ]] || fail 'rustc symlink escapes the restored PGO artifact'
[[ "$(realpath -e "$linker")" == "$mingw_root/"* ]] || fail 'linker symlink escapes the restored MinGW artifact'
[[ -d "$mingw_sysroot" && "$(realpath -e "$mingw_sysroot")" == "$mingw_root/"* ]] || fail 'missing restored MinGW sysroot'
configured_targets="$(./rbm/rbm showconf rust var/target "${common[@]}")"
mapfile -t targets < <(printf '%s\n' "$configured_targets" | tr ',' '\n' | sed -n '/^x86_64-.*windows.*gnullvm$/p')
[[ ${#targets[@]} -eq 1 && "${targets[0]}" == x86_64-pc-windows-gnullvm ]] || fail 'could not derive the pinned Firefox Windows x86_64 Rust target'
target="${targets[0]}"
export PATH="$rust_sysroot/bin:$mingw_root/bin:$PATH"
"$rustc" --version --verbose | tee "$RUNNER_TEMP/pgo-rust-compiler-version.txt"
reported_sysroot="$("$rustc" --print sysroot)"
[[ "$(realpath -e "$reported_sysroot")" == "$rust_sysroot" ]] || fail 'rustc selected a sysroot outside the restored PGO artifact'
libdir="$("$rustc" --sysroot "$rust_sysroot" --print target-libdir --target "$target")"
[[ -d "$libdir" && "$(realpath -e "$libdir")" == "$rust_sysroot/lib/rustlib/$target/lib" ]] || fail 'rustc selected a target libdir outside the restored PGO artifact'
echo "rustc sysroot: $rust_sysroot"; echo "rustc target libdir ($target): $libdir"
echo "Windows linker: $linker"; echo "Windows linker sysroot: $mingw_sysroot"
# Inventory metadata is diagnostic only; the compile/link below is the functional proof.
find -L "$libdir" -maxdepth 1 -type f -printf '%f %s bytes\n' | sort | tee "$RUNNER_TEMP/pgo-rust-runtime-inventory.log"
cat > "$RUNNER_TEMP/pgo-rust-preflight.rs" <<'RS'
fn main() { println!("pgo rust preflight"); }
RS
profile="$RUNNER_TEMP/pgo-rust-profile"; mkdir -p "$profile"
"$rustc" --sysroot "$rust_sysroot" --target "$target" \
  -C "linker=$linker" -C "link-arg=--sysroot=$mingw_sysroot" \
  -C "profile-generate=$profile" "$RUNNER_TEMP/pgo-rust-preflight.rs" -o "$RUNNER_TEMP/pgo-rust-preflight.exe"
test -s "$RUNNER_TEMP/pgo-rust-preflight.exe"
echo "PGO Rust preflight compiled and linked successfully for $target"
