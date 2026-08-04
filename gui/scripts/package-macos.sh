#!/usr/bin/env bash
#
# Package Notary as a single, self-contained macOS .app.
#
# The bundle carries two executables side by side in Contents/MacOS:
#
#   Notary.app/Contents/MacOS/notary   the GUI (CFBundleExecutable)
#   Notary.app/Contents/MacOS/signer       the daemon it supervises
#
# so one download brings up both: at launch the GUI discovers the `signer`
# sitting beside it and spawns it (see bundledDaemonPath in src/main.zig). No
# SIGNER_BIN, no second download. The key still only ever lives in the daemon
# child.
#
# The daemon binary is built from the `daemon/` package in this repo; this
# script does not build it — point --signer at a prebuilt binary (or build it:
# `cd ../daemon && zig build -Doptimize=ReleaseFast`).
#
# Usage:
#   scripts/package-macos.sh [options]
#     --signer PATH     signer daemon binary to bundle
#                       (default: $SIGNER_BIN, else ../daemon/zig-out/bin/signer)
#     --signing MODE    none | adhoc | identity     (default: adhoc)
#     --identity NAME   codesign identity, required for --signing identity
#                       (e.g. "Developer ID Application: Your Name (TEAMID)")
#     --output DIR      directory to write the .app into (default: dist)
#     -h, --help
#
# Ad-hoc signing is enough to run the bundle locally. A distributable, Gatekeeper
# -friendly build needs --signing identity plus notarization + stapling, which
# require your Apple Developer credentials and are left to you.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

signer_bin="${SIGNER_BIN:-}"
signing="adhoc"
identity=""
outdir="dist"
app_name="Notary.app"

usage() { sed -n '2,38p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --signer)   signer_bin="${2:?}"; shift 2 ;;
    --signing)  signing="${2:?}"; shift 2 ;;
    --identity) identity="${2:?}"; shift 2 ;;
    --output)   outdir="${2:?}"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$signing" in
  none|adhoc) ;;
  identity) [ -n "$identity" ] || { echo "error: --signing identity requires --identity <name>" >&2; exit 2; } ;;
  *) echo "error: --signing must be none, adhoc, or identity" >&2; exit 2 ;;
esac

# Locate the daemon binary if one wasn't given.
if [ -z "$signer_bin" ]; then
  for cand in "$root/../daemon/zig-out/bin/signer"; do
    [ -x "$cand" ] && { signer_bin="$cand"; break; }
  done
fi
if [ -z "$signer_bin" ] || [ ! -x "$signer_bin" ]; then
  echo "error: signer daemon binary not found or not executable: ${signer_bin:-<none>}" >&2
  echo "  build it:  (cd ../daemon && zig build -Doptimize=ReleaseFast)" >&2
  echo "  or pass:   --signer <path>   (or set SIGNER_BIN)" >&2
  exit 1
fi
# Absolutize so the copy works regardless of cwd.
signer_bin="$(cd "$(dirname "$signer_bin")" && pwd)/$(basename "$signer_bin")"

echo "==> building the GUI (native build, ReleaseFast)"
native build
gui_bin="$root/zig-out/bin/notary"
[ -x "$gui_bin" ] || { echo "error: $gui_bin missing after native build" >&2; exit 1; }

app="$outdir/$app_name"
echo "==> packaging an unsigned bundle at $app"
rm -rf "$app"
mkdir -p "$outdir"
# Package unsigned: we inject the daemon and then sign inside-out, so the
# packager must not sign first (that signature would break on injection).
native package --target macos --signing none --binary "$gui_bin" --output "$app" >/dev/null

echo "==> bundling the signer daemon into Contents/MacOS/signer"
cp "$signer_bin" "$app/Contents/MacOS/signer"
chmod +x "$app/Contents/MacOS/signer"

# Sign inside-out: the nested helper first, then the bundle (Apple's order).
case "$signing" in
  none)
    echo "==> leaving the bundle unsigned (--signing none)" ;;
  adhoc)
    echo "==> ad-hoc signing the daemon, then the bundle"
    codesign --force --sign - "$app/Contents/MacOS/signer"
    codesign --force --sign - "$app" ;;
  identity)
    echo "==> signing with \"$identity\" (hardened runtime + timestamp)"
    codesign --force --options runtime --timestamp --sign "$identity" "$app/Contents/MacOS/signer"
    codesign --force --options runtime --timestamp --sign "$identity" "$app" ;;
esac

if [ "$signing" != "none" ]; then
  codesign --verify --strict "$app"
  codesign --verify --strict "$app/Contents/MacOS/signer"
  echo "==> signatures verified"
fi

echo
echo "built: $app"
du -sh "$app" | awk '{printf "  size:   %s\n", $1}'
echo "  binaries in Contents/MacOS:"
/bin/ls -1 "$app/Contents/MacOS" | sed 's/^/    /'
