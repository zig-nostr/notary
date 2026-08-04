#!/bin/bash
#
# Notary - one-line macOS installer.
#
#   curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
#
# Downloads the latest release, verifies its SHA-256, installs Notary.app to
# /Applications (or ~/Applications), clears the download-quarantine flag so it
# opens without a Gatekeeper detour, and launches it. Notary is ad-hoc signed
# (not notarized) on purpose - it holds your keys, so the trust anchor is a build
# you can reproduce, not an Apple signature. Read this script and build from
# source (https://github.com/zig-nostr/notary#build) if you'd rather.
#
set -euo pipefail

say()  { printf '\033[1m==>\033[0m %s\n' "$1"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# All work happens inside main(), invoked on the very last line. That way bash
# runs nothing until it has downloaded and parsed the whole script, so a
# truncated `curl | bash` (a dropped connection mid-stream) can never execute a
# half-read script - it just does nothing.
main() {
  local repo="zig-nostr/notary"
  local app="Notary.app"

  # --- platform checks -----------------------------------------------------
  [ "$(uname -s)" = "Darwin" ] || die "Notary is a macOS app; this installer is macOS-only."
  [ "$(uname -m)" = "arm64" ] || die "Notary ships for Apple Silicon (arm64) only. On an Intel Mac, build from source: https://github.com/$repo#build"

  local tool
  for tool in curl shasum ditto xattr; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
  done

  # --- find the latest release asset ---------------------------------------
  say "Finding the latest Notary release..."
  local api="https://api.github.com/repos/$repo/releases/latest"
  local json
  json="$(curl -fsSL "$api")" || die "could not reach the GitHub API."

  local tag url digest
  tag="$(printf '%s' "$json" | grep -o '"tag_name":[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
  url="$(printf '%s' "$json" | grep -o '"browser_download_url":[[:space:]]*"[^"]*macos\.zip"' | head -1 | sed -E 's/.*"(https[^"]+)".*/\1/')"
  digest="$(printf '%s' "$json" | grep -o 'sha256:[0-9a-f]\{64\}' | head -1 | cut -d: -f2)"

  [ -n "$url" ] || die "no macOS build found on the latest release (${tag:-unknown})."
  say "Latest release: ${tag:-unknown}"

  # --- download + verify ---------------------------------------------------
  local zip
  # tmp is intentionally global (not local): the EXIT trap runs after main()
  # returns, where a local would be out of scope. ${tmp:-} keeps set -u happy.
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp:-}"' EXIT
  zip="$tmp/notary-macos.zip"

  say "Downloading $(basename "$url")..."
  curl -fSL --progress-bar -o "$zip" "$url" || die "download failed."

  if [ -n "$digest" ]; then
    local got
    got="$(shasum -a 256 "$zip" | awk '{print $1}')"
    [ "$got" = "$digest" ] || die "checksum mismatch (expected $digest, got $got). Aborting."
    say "SHA-256 verified."
  else
    say "No published checksum for this release; skipping verification."
  fi

  # --- unpack --------------------------------------------------------------
  say "Unpacking..."
  ditto -x -k "$zip" "$tmp/unpack" || die "could not unzip the download."
  local src="$tmp/unpack/$app"
  [ -d "$src" ] || die "the download did not contain $app."

  # --- choose an install location we can actually write to -----------------
  local dest
  if [ -w "/Applications" ] || { [ ! -e "/Applications/$app" ] && mkdir -p "/Applications" 2>/dev/null && [ -w "/Applications" ]; }; then
    dest="/Applications"
  else
    dest="$HOME/Applications"
    mkdir -p "$dest"
  fi
  [ -n "$dest" ] || die "could not determine an install location."

  # --- install (replace any existing copy) ---------------------------------
  if [ -e "$dest/$app" ]; then
    say "Replacing the existing ${app} in ${dest}..."
    # ${var:?} guards against ever expanding to "/" if a variable were empty.
    rm -rf "${dest:?}/${app:?}" || die "could not remove the existing $dest/$app (is it running?)."
  fi
  ditto "$src" "$dest/$app" || die "could not install to $dest."

  # --- clear quarantine so it opens without a Gatekeeper detour -------------
  xattr -dr com.apple.quarantine "$dest/$app" 2>/dev/null || true

  say "Installed $app to $dest."
  say "Opening Notary..."
  open "$dest/$app" || say "Open it from $dest/$app whenever you're ready."
}

main "$@"
