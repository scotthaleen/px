#!/bin/sh
# Install public GitHub release binaries; never run them or change PX state.
set -eu
umask 077

fail() { printf 'px installer: %s\n' "$*" >&2; exit 1; }
version=${PX_VERSION:-latest}
dest=${PX_INSTALL_DIR:-"$HOME/.local/bin"}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--dir)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            case "$1" in --version) version=$2 ;; --dir) dest=$2 ;; esac
            shift 2 ;;
        --help|-h)
            printf '%s\n' 'Usage: sh install.sh [--version YYYY.MM.DD[.N]|latest] [--dir PATH]' 'Defaults: PX_VERSION or latest; PX_INSTALL_DIR or ~/.local/bin'
            exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[ -n "$dest" ] || fail 'installation directory is empty'
case "$dest" in /*) ;; *) dest="$PWD/$dest" ;; esac
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) fail 'supported systems: Linux and macOS' ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) fail 'supported architectures: amd64 and arm64' ;; esac
for tool in curl tar mktemp awk; do command -v "$tool" >/dev/null 2>&1 || fail "required command: $tool"; done
if command -v sha256sum >/dev/null 2>&1; then hash=sha256sum
elif command -v shasum >/dev/null 2>&1; then hash=shasum
else fail 'sha256sum or shasum is required'; fi
download() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 30 --max-time 300 "$@"; }
repo=https://github.com/scotthaleen/px
if [ "$version" = latest ]; then
    url=$(download --output /dev/null --write-out '%{url_effective}' "$repo/releases/latest")
    case "$url" in "$repo/releases/tag/"*) version=${url##*/} ;; *) fail 'could not resolve latest GitHub release' ;; esac
fi
printf '%s\n' "$version" | LC_ALL=C awk '/^[0-9][0-9][0-9][0-9]\.[0-9][0-9]\.[0-9][0-9](\.[0-9]+)?$/ {ok++} END {exit !(NR == 1 && ok == 1)}' || fail 'version must be YYYY.MM.DD[.N], without a v prefix'
archive="px-$version-$os-$arch.tar.gz"
work=$(mktemp -d)
lock=
changed_px=0
changed_server=0
success=0
cleanup() {
    status=$?
    trap - 0 HUP INT TERM
    if [ -n "$lock" ]; then
        rollback_failed=0
        if [ "$success" -eq 0 ]; then
            for name in px px-server; do
                case "$name" in px) changed=$changed_px ;; *) changed=$changed_server ;; esac
                [ "$changed" -eq 1 ] || continue
                if [ -f "$lock/$name.old" ]; then
                    mv -f "$lock/$name.old" "$dest/$name" || rollback_failed=1
                else
                    rm -f "$dest/$name" || rollback_failed=1
                fi
            done
        fi
        if [ "$rollback_failed" -eq 0 ]; then rm -rf "$lock"
        else printf 'Rollback failed; backups retained in %s\n' "$lock" >&2; status=1; fi
    fi
    rm -rf "$work"
    exit "$status"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
download --output "$work/$archive" "$repo/releases/download/$version/$archive"
download --output "$work/SHA256SUMS" "$repo/releases/download/$version/SHA256SUMS"
expected=$(awk -v name="$archive" '$2 == name { count++; digest=$1; if (NF != 2) bad=1 } END { if (count != 1 || bad || length(digest) != 64 || digest ~ /[^0-9a-fA-F]/) exit 1; print tolower(digest) }' "$work/SHA256SUMS") || fail 'expected exactly one valid archive checksum'
if [ "$hash" = sha256sum ]; then actual=$(sha256sum "$work/$archive")
else actual=$(shasum -a 256 "$work/$archive"); fi
actual=${actual%% *}
[ "$actual" = "$expected" ] || fail 'SHA-256 verification failed'
# Require the packager's flat regular-file layout. Extract to stdout, not archive paths.
tar -tzf "$work/$archive" > "$work/entries"
awk '{ if ($0 != "px" && $0 != "px-server" && $0 != "LICENSE" && $0 != "THIRD_PARTY_NOTICES.md" && $0 != "release-manifest.json") exit 1; if (seen[$0]++) exit 1; count++ } END { if (count != 5) exit 1 }' "$work/entries" || fail 'unexpected archive layout'
tar -tvzf "$work/$archive" > "$work/types"
awk 'substr($0,1,1) != "-" {exit 1}' "$work/types" || fail 'archive contains non-regular files'
mkdir -p "$dest"
mkdir "$dest/.px-install.lock" 2>/dev/null || fail "another installer or recovery directory exists: $dest/.px-install.lock"
lock="$dest/.px-install.lock"
for name in px px-server; do
    [ ! -L "$dest/$name" ] || fail "refusing to replace symlink: $dest/$name"
    if [ -e "$dest/$name" ]; then
        [ -f "$dest/$name" ] || fail "not a regular file: $dest/$name"
        cp -p "$dest/$name" "$lock/$name.old"
    fi
    tar -xOzf "$work/$archive" "$name" > "$lock/$name.new"
    [ -s "$lock/$name.new" ] || fail "empty binary: $name"
    chmod 0755 "$lock/$name.new"
done
changed_px=1
mv -f "$lock/px.new" "$dest/px"
changed_server=1
mv -f "$lock/px-server.new" "$dest/px-server"
success=1
printf 'Installed PX %s (%s/%s) into %s\nAdd this directory to PATH if needed. Startup and enrollment are unchanged.\n' "$version" "$os" "$arch" "$dest"
