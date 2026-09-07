#!/bin/bash
#
# Notary - one-line Linux installer.
#
#   curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-linux.sh | bash
#
# Downloads the latest release for this architecture, verifies its SHA-256,
# installs into ~/.local (no root, nothing outside your home), puts Notary in
# the launcher, and starts it.
#
# One download brings up both halves: the window, and the `signer` daemon it
# spawns, which is where your key actually lives. They install side by side
# because the window finds the daemon beside its own executable.
#
# Notary needs GTK 4 at runtime and nothing else: the toolkit's Linux host links
# gtk4 and libdl, and the WebKit layer is compiled out because Notary draws on a
# canvas rather than in a browser.
#
# It does need a RECENT distribution, though. The toolkit's Linux host declares a
# GTK floor of 4.10 (its own source: "This host's GTK floor is 4.10"), and the
# release binaries are built on Ubuntu 24.04, so they want glibc 2.38 or newer.
# Both land on the same generation: Ubuntu 23.10+, Debian 13+, Fedora 39+.
# Ubuntu 22.04 and Debian 12 cannot run this, and are checked for below rather
# than left to fail with a loader error after a successful-looking install.
#
# Notary is not signed or notarised anywhere, on purpose. It holds your key, so
# the trust anchor is a build you can reproduce, not a signature you cannot
# inspect. Read this script, and build from source
# (https://github.com/zig-nostr/notary#build) if you would rather.
#
set -euo pipefail

# Script scope, not `main`'s. The EXIT trap runs after `main` returns, and a
# `local` is gone by then: under `set -u` the cleanup then dies on its own
# variable, which is a confusing failure at the end of a successful install.
workdir=""
cleanup() { [ -n "$workdir" ] && rm -rf "$workdir"; }
trap cleanup EXIT

say() { printf '\033[1m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33mnote:\033[0m %s\n' "$1"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# All work happens inside main(), invoked on the very last line, so bash runs
# nothing until the whole script has been read. A truncated `curl | bash` (a
# connection dropped mid-stream) then does nothing at all rather than half of
# an install.
main() {
  local repo="zig-nostr/notary"
  # A tarball already on disk, instead of the latest published release. For
  # installing without a network, and for trying a build before it is a release,
  # which is how this script was first tested at all.
  local archive=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --archive) archive="${2:?--archive needs a path}"; shift 2 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  # Only what the chosen path actually uses. `curl` belongs to the download,
  # and demanding it for `--archive` refuses an offline install for a tool that
  # install would never call.
  for tool in sha256sum tar; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required and is not on PATH."
  done

  # GTK 4 is the one runtime dependency, and finding out it is missing when the
  # window fails to open is worse than being told now. Checked by loader rather
  # than by package name, because the package is called libgtk-4-1 on Debian and
  # Ubuntu, gtk4 on Fedora and Arch, and something else again elsewhere.
  #
  # `grep -c ... || true`, NOT `grep -q`. Under `set -o pipefail` a matching
  # `grep -q` exits at once, `ldconfig` dies of SIGPIPE, and the pipeline reports
  # THAT rather than the match, so the guard fires on a machine that has GTK. It
  # fires on one that does not either, because grep exits 1 there, which makes it
  # a check that can never pass. `package-linux.sh` carries a comment about this
  # exact trap and I wrote it here anyway.
  if command -v ldconfig >/dev/null 2>&1; then
    local gtk
    gtk="$(ldconfig -p 2>/dev/null | grep -c "libgtk-4\.so" || true)"
    [ "$gtk" != "0" ] || die "GTK 4 is missing. Install it first: apt install libgtk-4-1, dnf install gtk4, or pacman -S gtk4."
  fi

  # The distribution floor, checked BEFORE downloading anything or writing files.
  # Without this an Ubuntu 22.04 user gets a clean install, a verified digest, a
  # cheerful "Installed Notary", and then `version GLIBC_2.38 not found` the
  # first time they open it. For an app that holds a key, "it will not start"
  # should never be something you discover after trusting it with one.
  #
  # glibc is the proxy for both floors. The real constraints are glibc 2.38 (the
  # binaries are built on Ubuntu 24.04) and GTK 4.10 (the toolkit's own declared
  # floor), and every distribution that has one has the other, so one check
  # answers both and needs no -dev package to run.
  local glibc
  glibc="$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+$' || true)"
  if [ -n "$glibc" ]; then
    local major minor
    major="${glibc%%.*}"
    minor="${glibc##*.}"
    if [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 38 ]; }; then
      die "this build needs glibc 2.38 or newer and GTK 4.10 or newer; you have glibc $glibc.
       That means Ubuntu 23.10+, Debian 13+, or Fedora 39+. Ubuntu 22.04 and
       Debian 12 are too old for it. Building from source on your own system
       works if its GTK is 4.10 or newer: https://github.com/zig-nostr/notary#build"
    fi
  fi

  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | aarch64) ;;
    *) die "no build for $arch. Notary publishes x86_64 and aarch64; build from source for anything else." ;;
  esac

  local tmp
  tmp="$(mktemp -d)"
  workdir="$tmp"

  local tag asset
  if [ -n "$archive" ]; then
    [ -f "$archive" ] || die "$archive does not exist."
    asset="$(basename "$archive")"
    tag="local"
    say "Installing from $archive"
    cp "$archive" "$tmp/$asset"
    installFrom "$tmp" "$asset" "$tag"
    return
  fi

  command -v curl >/dev/null 2>&1 || die "curl is required to download a release (or pass --archive <file>)."

  say "Looking up the latest release..."
  local api resp code json url
  api="https://api.github.com/repos/$repo/releases/latest"
  # Not `curl -f`: -f collapses every HTTP answer into one exit code, so a rate
  # limit and a network failure become the same unhelpful message. The status
  # comes back on its own line instead.
  resp="$(curl -sSL -w '\n%{http_code}' "$api")" || die "could not reach GitHub. Check your connection and try again."
  code="$(printf '%s' "$resp" | tail -1)"
  json="$(printf '%s' "$resp" | sed '$d')"
  case "$code" in
    200) ;;
    403) die "GitHub rate-limited this machine. Wait a few minutes, or download the release by hand." ;;
    404) die "no published release found for $repo." ;;
    *) die "GitHub answered $code." ;;
  esac

  tag="$(printf '%s' "$json" | grep -o '"tag_name":[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
  [ -n "$tag" ] || die "could not read the release tag."
  asset="notary-${tag#v}-linux-$arch.tar.gz"
  url="https://github.com/$repo/releases/download/$tag/$asset"

  say "Downloading $asset..."
  curl -fSL --progress-bar -o "$tmp/$asset" "$url" || die "download failed. There may be no $arch build for $tag."

  # The digest is published beside the tarball rather than read out of the API
  # body, so a release whose notes were edited cannot change what this compares
  # against.
  if curl -fsSL -o "$tmp/$asset.sha256" "$url.sha256" 2>/dev/null; then
    local want got
    want="$(awk '{print $1}' "$tmp/$asset.sha256")"
    got="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
    [ "$want" = "$got" ] || die "the download does not match its published SHA-256. Not installing it."
    say "SHA-256 verified."
  else
    warn "no published SHA-256 for this release, so the download could not be verified."
  fi

  installFrom "$tmp" "$asset" "$tag"
}

# Unpacks an archive and installs it. Shared by the download path and by
# `--archive`, so a local install and a released one are the same install.
installFrom() {
  local tmp="$1" asset="$2" tag="$3"
  say "Unpacking..."
  tar -C "$tmp" -xzf "$tmp/$asset"
  local src
  src="$(find "$tmp" -maxdepth 1 -type d -name 'notary-*-linux-*' | head -1)"
  [ -n "$src" ] || die "the archive did not contain what was expected."
  for required in notary signer; do
    [ -x "$src/bin/$required" ] || die "$required is missing from the archive."
  done

  # ~/.local, so nothing needs root and nothing lands outside the home
  # directory. This is where the XDG spec puts a single user's own programs, and
  # it is what makes uninstalling "delete three paths".
  local prefix="$HOME/.local"
  say "Installing into $prefix..."
  mkdir -p "$prefix/bin" "$prefix/share/applications" "$prefix/share/icons/hicolor"

  # The window finds `signer` as a SIBLING of its own executable, so both go in
  # one directory or the daemon that holds the key is silently missing.
  install -m 0755 "$src/bin/notary" "$src/bin/signer" "$prefix/bin/"

  # The icons ship as app-icon.png, which is what the toolkit's packager names
  # every app's icon. Installed under that name they would collide with every
  # other app built the same way, so they are renamed on the way in and the
  # desktop entry is pointed at the new name below.
  local size_dir
  while IFS= read -r size_dir; do
    local size
    size="$(basename "$(dirname "$size_dir")")"
    mkdir -p "$prefix/share/icons/hicolor/$size/apps"
    install -m 0644 "$size_dir/app-icon.png" "$prefix/share/icons/hicolor/$size/apps/notary.png"
  done < <(find "$src/share/icons/hicolor" -type d -name apps 2>/dev/null)

  # Exec must be absolute. The entry ships with a bare executable name, which
  # only resolves if ~/.local/bin is on PATH, and the desktop environment that
  # launches a link handler does not necessarily have the PATH a shell does.
  # The packager writes the executable QUOTED (`Exec="notary"`), so the
  # replacement has to swallow the quotes rather than the name alone: matching
  # `.*notary` leaves the closing quote stranded and the entry is malformed.
  # The result is quoted too, because a home directory may contain a space.
  sed -E -e "s|^Exec=\"?[^\" ]*\"?|Exec=\"$prefix/bin/notary\"|" \
         -e "s|^Icon=app-icon$|Icon=notary|" \
      "$src/share/applications/notary.desktop" > "$prefix/share/applications/notary.desktop"
  chmod 0644 "$prefix/share/applications/notary.desktop"

  # Best effort: a desktop environment that indexes on its own will find these
  # anyway, and a machine with neither tool is not broken.
  command -v update-desktop-database >/dev/null 2>&1 &&
    update-desktop-database "$prefix/share/applications" 2>/dev/null || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 &&
    gtk-update-icon-cache -f -t "$prefix/share/icons/hicolor" 2>/dev/null || true
  case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *) warn "$prefix/bin is not on your PATH. Add it to run 'notary' from a terminal; the desktop entry works either way." ;;
  esac

  say "Installed Notary $tag."
  say "Starting it..."
  "$prefix/bin/notary" >/dev/null 2>&1 &
  disown 2>/dev/null || true
}

main "$@"
