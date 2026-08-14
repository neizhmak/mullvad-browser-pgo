#!/usr/bin/env bash
set -euo pipefail
: "${UPSTREAM:?}"; : "${RUNNER_TEMP:?}"
common=(--target alpha --target mullvadbrowser-windows-x86_64 --target pgo-generate)
cd "$UPSTREAM"
rust_filename="$(./rbm/rbm showconf rust filename "${common[@]}")"
official_filename="$(./rbm/rbm showconf rust filename --target alpha --target mullvadbrowser-windows-x86_64)"
[[ "$rust_filename" != "$official_filename" && "$rust_filename" == *-profiler* ]] || { echo 'PGO Rust did not resolve to its distinct profiler identity' >&2; exit 1; }
rust_archive="$(find out/rust -type f -name "$rust_filename" -print -quit)"
[[ -n "$rust_archive" ]] || { echo "selected PGO Rust input is missing: $rust_filename" >&2; exit 1; }
echo "Exact PGO Rust RBM input: $rust_archive (sha256=$(sha256sum "$rust_archive" | cut -d' ' -f1), size=$(stat -c%s "$rust_archive"))"
tools="$RUNNER_TEMP/pgo-rust-preflight-tools"; rm -rf "$tools"; mkdir -p "$tools/rust" "$tools/mingw"
tar -xaf "$rust_archive" -C "$tools/rust"
mingw_archive="$(find out/mingw-w64-clang -type f -print -quit)"; test -n "$mingw_archive"; tar -xaf "$mingw_archive" -C "$tools/mingw"
rustc="$(find "$tools/rust" -type f -path '*/bin/rustc' -perm -111 -print -quit)"; test -n "$rustc"
mingw_bin="$(dirname "$(find "$tools/mingw" -type f -name x86_64-w64-mingw32-clang -perm -111 -print -quit)")"; test -d "$mingw_bin"
target="$(./rbm/rbm showconf rust var/target "${common[@]}" | tr ',' '\n' | sed -n '/^x86_64-.*windows.*gnullvm$/p')"
[[ $(printf '%s\n' "$target" | sed '/^$/d' | wc -l) -eq 1 ]] || { echo 'could not derive one Firefox Windows x86_64 Rust target' >&2; exit 1; }
export PATH="$mingw_bin:$PATH"
"$rustc" --version --verbose
sysroot="$($rustc --print sysroot)"; libdir="$($rustc --print target-libdir --target "$target")"
echo "rustc sysroot: $sysroot"; echo "rustc target libdir ($target): $libdir"
[[ "$sysroot" == "$tools/rust"/* ]] || { echo 'rustc selected a sysroot outside the restored PGO artifact' >&2; exit 1; }
# Inventory metadata is diagnostic only; the compile/link below is the functional proof.
find "$libdir" -maxdepth 1 -type f -printf '%f %s bytes\n' | sort | tee "$RUNNER_TEMP/pgo-rust-runtime-inventory.log"
cat > "$RUNNER_TEMP/pgo-rust-preflight.rs" <<'RS'
fn main() { println!("pgo rust preflight"); }
RS
profile="$RUNNER_TEMP/pgo-rust-profile"; mkdir -p "$profile"
"$rustc" --target "$target" -C "profile-generate=$profile" "$RUNNER_TEMP/pgo-rust-preflight.rs" -o "$RUNNER_TEMP/pgo-rust-preflight.exe"
test -s "$RUNNER_TEMP/pgo-rust-preflight.exe"
echo "PGO Rust preflight compiled and linked successfully for $target"
