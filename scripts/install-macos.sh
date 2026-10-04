#!/bin/bash
#
# Notary - the old address of the macOS installer.
#
#   curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
#
# One installer covers macOS and Linux now, scripts/install.sh, and this file
# only runs it with the same arguments, so links to this address keep working.
# It runs the copy beside this file when there is one (a checkout), and
# otherwise fetches install.sh from the same place this file came from.
#
set -euo pipefail

# Empty when read from a pipe, so a piped run never picks up a stray
# install.sh from whatever directory it happens to be started in.
self="${BASH_SOURCE[0]:-}"

die() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# Everything runs from main(), called on the last line, so a truncated
# `curl | bash` does nothing at all.
main() {
  if [ -n "$self" ] && [ -f "$(dirname "$self")/install.sh" ]; then
    exec bash "$(dirname "$self")/install.sh" "$@"
  fi
  command -v curl >/dev/null 2>&1 || die "curl is required to fetch the installer."
  # NOTARY_INSTALLER_URL exists so CI can prove this path against the
  # install.sh under review rather than the one already on main.
  local url="${NOTARY_INSTALLER_URL:-https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install.sh}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp:-}"' EXIT
  curl -fsSL --retry 2 -o "$tmp/install.sh" "$url" || die "could not fetch $url."
  bash "$tmp/install.sh" "$@"
}

main "$@"
