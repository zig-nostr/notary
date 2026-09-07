#!/bin/bash
#
# Packages Notary for Linux: the window, the daemon it supervises, and the
# desktop entry that puts it in the launcher, in one tarball.
#
#   gui/scripts/package-linux.sh --signer <path> [--output dist]
#
# RUN THIS ON LINUX. Not a preference: the toolkit's Linux host links gtk4, and
# a Mac has no Linux copy of it, so a cross build from macOS compiles every Zig
# module and then dies at the link.
#
# The tarball carries two executables side by side in bin/:
#
#   notary   the window
#   signer   the daemon it spawns, which is where the key lives
#
# so one download brings up both. At launch the window finds the `signer`
# sitting beside it (bundledDaemonPath in src/main.zig), exactly as it finds it
# in Contents/MacOS on macOS. No SIGNER_BIN, no second download.
#
# There is nothing to sign and nothing to notarise here. A Linux tarball is
# bytes in a directory, and the trust anchor is the same as it is on macOS: a
# build you can reproduce from source.
set -euo pipefail

say() { printf '\033[1m==>\033[0m %s\n' "$1"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

gui_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
outdir="$gui_root/dist"
signer="${SIGNER_BIN:-$gui_root/../daemon/zig-out/bin/signer}"
while [ $# -gt 0 ]; do
  case "$1" in
    --output) outdir="${2:?--output needs a path}"; shift 2 ;;
    --signer) signer="${2:?--signer needs a path}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ "$(uname -s)" = "Linux" ] || die "packaging for Linux needs Linux (the gtk4 link does not cross)."
command -v native >/dev/null 2>&1 || die "the Native SDK CLI is not on PATH (npm install -g @native-sdk/cli)."
pkg-config --exists gtk4 2>/dev/null || die "gtk4 development files are missing (apt install libgtk-4-dev)."
[ -x "$signer" ] || die "no signer daemon at '$signer'. Build it: (cd daemon && zig build -Doptimize=ReleaseFast)"

# Resolved BEFORE the cd, or a relative --signer silently becomes a path
# relative to gui/ and the copy fails after the build has already run. The
# check above passed for exactly that reason: it ran in the caller's directory.
signer="$(cd "$(dirname "$signer")" && pwd)/$(basename "$signer")"

cd "$gui_root"
version="$(sed -n 's/^ *\.version = "\(.*\)",$/\1/p' app.zon | head -1)"
[ -n "$version" ] || die "could not read the version from app.zon"
arch="$(uname -m)"
stage="$outdir/notary-$version-linux-$arch"

# Cleared first: `native package` does not build, it carries whatever is already
# sitting in zig-out. On a developer's machine that is routinely the last thing
# they were debugging, and the specific hazard is `-Dautomation=true`, which
# embeds a server that drives the UI through the real input path in an app that
# holds somebody's key.
say "Clearing zig-out so nothing stale or instrumented can be picked up..."
rm -rf zig-out "$stage" "$outdir/notary-$version-linux-$arch.tar.gz"

say "Building (ReleaseFast, no automation)..."
native build .

# `grep -c ... || true`, not `grep -q`: under `set -o pipefail` a matching
# `grep -q` exits early, `strings` dies of SIGPIPE, and the pipeline reports
# THAT rather than the match, so the check waves an instrumented binary
# straight through.
hits="$(strings zig-out/bin/notary | grep -c "native-sdk-automation" || true)"
[ "$hits" = "0" ] || die "the built binary carries the automation server ($hits marker(s)). Refusing to package it."

say "Packaging..."
native package --target linux --output "$stage"

say "Injecting the daemon beside the window..."
cp "$signer" "$stage/bin/signer"
chmod +x "$stage/bin/"*

# Both assertions, both directions, for the reason the macOS script gives: the
# window degrades SILENTLY when the daemon is missing beside it, so a release is
# the wrong place to find that out; and anything else that wandered into
# zig-out/bin would otherwise ride along.
for required in notary signer; do
  [ -x "$stage/bin/$required" ] || die "$required is missing from the package."
done
for bin in "$stage/bin/"*; do
  case "$(basename "$bin")" in
    notary | signer) ;;
    *) die "$(basename "$bin") is in the package and is not a binary Notary runs. If it belongs, name it here; if it does not, stop installing it in build.zig." ;;
  esac
done

# What the packager wrote, checked rather than assumed.
desktop="$stage/share/applications/notary.desktop"
[ -f "$desktop" ] || die "the packager wrote no desktop entry, so Notary would not appear in the launcher."

say "Compressing..."
tar -C "$outdir" -czf "$outdir/notary-$version-linux-$arch.tar.gz" "notary-$version-linux-$arch"
( cd "$outdir" && sha256sum "notary-$version-linux-$arch.tar.gz" > "notary-$version-linux-$arch.tar.gz.sha256" )

say "Built $outdir/notary-$version-linux-$arch.tar.gz"
say "Carries: $(cd "$stage/bin" && echo *)"
