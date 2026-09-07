#!/bin/sh
# Hermetic installer integration tests. No release binaries are executed.
set -eu
root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
mkdir -p "$root/tmp"
scratch=$(mktemp -d "$root/tmp/install-test.XXXXXX")
cleanup() {
    status=$?
    if [ "$status" -ne 0 ] && [ -f "$scratch/output" ]; then cat "$scratch/output" >&2; fi
    rm -rf "$scratch"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
export HOME="$scratch/home" PX_HOME="$scratch/px-home" TMPDIR="$scratch/temp"
export FIXTURES="$scratch/releases"
export PATH="$root/tests/install-mocks:$PATH"
export TEST_OS=Linux TEST_ARCH=x86_64
unset PX_VERSION PX_INSTALL_DIR FAIL_DOWNLOAD FAIL_REPLACE
mkdir -p "$HOME" "$TMPDIR" "$FIXTURES" "$scratch/contents"
for name in px px-server LICENSE THIRD_PARTY_NOTICES.md release-manifest.json; do
    printf 'fixture %s\n' "$name" > "$scratch/contents/$name"
done
checksum() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"
    else shasum -a 256 "$1"; fi
}
package() {
    archive="px-2026.09.07.1-$1-$2.tar.gz"
    tar -czf "$FIXTURES/$archive" -C "$scratch/contents" px px-server LICENSE THIRD_PARTY_NOTICES.md release-manifest.json
    digest=$(checksum "$FIXTURES/$archive")
    printf '%s  %s\n' "${digest%% *}" "$archive" > "$FIXTURES/SHA256SUMS"
}
run() { sh "$root/install.sh" "$@" > "$scratch/output" 2>&1; }
unchanged() {
    [ "$(cat "$HOME/.local/bin/px")" = old-px ]
    [ "$(cat "$HOME/.local/bin/px-server")" = old-server ]
    [ ! -e "$HOME/.local/bin/.px-install.lock" ]
    [ -z "$(ls -A "$TMPDIR")" ]
}
reject() {
    if run "$@"; then printf 'Expected failure\n' >&2; exit 1; fi
    unchanged
}
package linux amd64
if (FAIL_REPLACE=1 run); then exit 1; fi
[ ! -e "$HOME/.local/bin/px" ]
[ ! -e "$HOME/.local/bin/px-server" ]
[ ! -e "$HOME/.local/bin/.px-install.lock" ]
[ -z "$(ls -A "$TMPDIR")" ]
for platform in linux darwin; do
    case "$platform" in linux) TEST_OS=Linux ;; *) TEST_OS=Darwin ;; esac
    export TEST_OS
    for arch in amd64 arm64; do
        case "$arch" in amd64) TEST_ARCH=x86_64 ;; *) TEST_ARCH=aarch64 ;; esac
        export TEST_ARCH
        package "$platform" "$arch"
        run
        cmp "$scratch/contents/px" "$HOME/.local/bin/px"
        cmp "$scratch/contents/px-server" "$HOME/.local/bin/px-server"
        [ -x "$HOME/.local/bin/px" ]
        [ ! -e "$HOME/.local/bin/.px-install.lock" ]
    done
done
run --version 2026.09.07.1 --dir "$scratch/custom bin"
cmp "$scratch/contents/px-server" "$scratch/custom bin/px-server"
(PX_VERSION=2026.09.07.1 PX_INSTALL_DIR="$scratch/env bin" run)
cmp "$scratch/contents/px" "$scratch/env bin/px"
printf old-px > "$HOME/.local/bin/px"
printf old-server > "$HOME/.local/bin/px-server"
(FAIL_DOWNLOAD=1 reject)
(FAIL_REPLACE=1 reject)
(TEST_OS=FreeBSD reject)
(TEST_ARCH=i386 reject)
reject --version v2026.09.07
reject --version '../bad'
reject --version '2026.09.07.1
bad'
reject --dir
reject --unknown
cp "$FIXTURES/SHA256SUMS" "$scratch/good-sums"
printf '%064d  %s\n' 0 "$archive" > "$FIXTURES/SHA256SUMS"
reject
cat "$scratch/good-sums" "$scratch/good-sums" > "$FIXTURES/SHA256SUMS"
reject
printf 'invalid  unrelated.tar.gz\n' > "$FIXTURES/SHA256SUMS"
reject
cp "$scratch/good-sums" "$FIXTURES/SHA256SUMS"
printf corrupt >> "$FIXTURES/$archive"
reject
package darwin arm64
rm "$scratch/contents/px-server"
ln -s px "$scratch/contents/px-server"
package darwin arm64
reject
rm "$scratch/contents/px-server"
printf server > "$scratch/contents/px-server"
package darwin arm64
rm "$HOME/.local/bin/px-server"
ln -s "$scratch/contents/px-server" "$HOME/.local/bin/px-server"
if run; then exit 1; fi
[ -L "$HOME/.local/bin/px-server" ]
[ "$(cat "$HOME/.local/bin/px")" = old-px ]
[ ! -e "$HOME/.local/bin/.px-install.lock" ]
[ -z "$(ls -A "$TMPDIR")" ]
[ ! -e "$PX_HOME" ]
printf 'Installer shell tests passed\n'
