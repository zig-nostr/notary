#!/bin/bash
#
# Notary - one-line installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install.sh | bash
#
# Finds the latest release for this system, verifies its SHA-256 against the
# digest published beside it, installs it, and starts it.
#
#   macOS (Apple Silicon): installs Notary.app to /Applications (or
#   ~/Applications), clears the download-quarantine flag so it opens without a
#   Gatekeeper detour, and opens it.
#
#   Linux (x86_64 and aarch64): installs into ~/.local (no root, nothing
#   outside your home), puts Notary in the launcher, and starts it.
#
# One download brings up both halves on either system: the window, and the
# `signer` daemon it spawns, which is where your key actually lives. They sit
# side by side because the window finds the daemon beside its own executable.
#
# Notary is ad-hoc signed on macOS and not signed at all on Linux, and not
# notarized anywhere, on purpose. It holds your key, so the trust anchor is a
# build you can reproduce, not a signature you cannot inspect. Read this
# script, and build from source (https://github.com/zig-nostr/notary#build) if
# you would rather.
#
# This file is served over `curl | bash`, and macOS runs it with bash 3.2. So it
# stays pure ASCII (a multibyte character next to a $variable under `set -u`
# aborts bash 3.2 before it has said anything) and uses nothing newer than bash
# 3.2. CI checks both. scripts/install-macos.sh and scripts/install-linux.sh
# are the old per-system addresses, kept as wrappers that run this file.
#
set -euo pipefail

# Script scope, not `main`'s. The EXIT trap runs after `main` returns, and a
# `local` is gone by then: under `set -u` the cleanup then dies on its own
# variable, which is a confusing failure at the end of a successful install.
workdir=""
# `return 0` on purpose. Without it the trap's last command is the failed
# `[ -n "$workdir" ]` of a run that never made a temp directory, and bash exits
# with THAT: `--help` reported failure, and so would any early exit that had not
# reached the download yet.
cleanup() {
  [ -n "$workdir" ] && rm -rf "$workdir"
  return 0
}
trap cleanup EXIT

say() { printf '\033[1m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33mnote:\033[0m %s\n' "$1"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

repo="zig-nostr/notary"

# The options, set once by `main` and read by the install steps.
opt_prefix=""
opt_no_open=0

usage() {
  printf 'usage: install.sh [options]\n\n'
  printf 'Installs Notary on macOS (Apple Silicon) or Linux (x86_64, aarch64).\n\n'
  printf '  --version <tag>   install this release (for example v0.11.2) instead of the latest\n'
  printf '  --archive <file>  install this release file instead of downloading one; a\n'
  printf '                    <file>.sha256 beside it is checked and has to match\n'
  printf '  --prefix <dir>    install here instead: the folder that gets Notary.app on\n'
  printf '                    macOS (default /Applications), the root of bin/ and share/\n'
  printf '                    on Linux (default ~/.local)\n'
  printf '  --no-open         install, but do not open or start Notary\n'
  printf '  -h, --help        show this\n'
}

# The SHA-256 of a file, by whichever tool this system has: `sha256sum` on
# Linux, `shasum` on macOS (which has carried it far longer than sha256sum).
sha256Of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Checks a file against a published `.sha256`, and refuses to go on otherwise.
#
# An empty expected digest compares equal to an empty computed one, and the
# whole check then reports success over nothing at all. Both sides are required
# to exist, and the expected one to be well formed, before either is trusted.
verify() {
  local file="$1" sums="$2" name="$3" want got
  want="$(awk '{print $1}' "$sums")"
  case "$want" in
    "" | *[!0-9a-f]*) die "the published SHA-256 for $name is empty or malformed. Not installing it." ;;
  esac
  [ "${#want}" -eq 64 ] || die "the published SHA-256 for $name is malformed. Not installing it."
  got="$(sha256Of "$file")"
  [ -n "$got" ] || die "could not compute the SHA-256 of $name. Not installing it."
  [ "$got" = "$want" ] || die "checksum mismatch: $name does not match its published SHA-256 (expected $want, got $got). Not installing it."
  say "SHA-256 verified."
}

# Whether GTK 4 is on this machine: `present`, `missing`, or `unknown`.
#
# `ldconfig` is the reliable answer and it lives in /usr/sbin, which Debian does
# NOT put on a normal user's PATH. Gating the whole check on
# `command -v ldconfig` therefore skipped it entirely on one of the three
# distributions this script names as supported: a Debian user without GTK 4 got
# a verified download, a cheerful "Installed Notary", and an app that dies on
# `libgtk-4.so.1` with the launch output thrown away. For an app that holds a
# key, "it will not start" is the worst thing to discover in silence. So it is
# looked for by absolute path too, and if there is no ldconfig at all the
# library directories are searched directly.
#
# `grep -c ... || true`, NOT `grep -q`. Under `set -o pipefail` a matching
# `grep -q` exits at once, `ldconfig` dies of SIGPIPE, and the pipeline reports
# THAT rather than the match, so the guard fires on a machine that HAS GTK. It
# fires on one that does not either, because grep exits 1 there, which makes it
# a check that can never pass. `grep -c` drains its input instead.
gtkStatus() {
  local ldc hits d
  for ldc in ldconfig /usr/sbin/ldconfig /sbin/ldconfig; do
    command -v "$ldc" >/dev/null 2>&1 || [ -x "$ldc" ] || continue
    hits="$("$ldc" -p 2>/dev/null | grep -c 'libgtk-4\.so' || true)"
    if [ "$hits" = "0" ]; then printf 'missing\n'; else printf 'present\n'; fi
    return
  done
  for d in /usr/lib /usr/lib64 /lib /lib64 /usr/local/lib /usr/lib/*-linux-gnu*; do
    [ -d "$d" ] || continue
    if compgen -G "$d/libgtk-4.so*" >/dev/null 2>&1; then printf 'present\n'; return; fi
  done
  # No ldconfig and nothing in the usual places. Refusing here would turn an
  # unusual layout into a refused install, so this reports that it cannot tell
  # and the caller warns rather than dies.
  printf 'unknown\n'
}

# Linux only, and run BEFORE anything is downloaded or written.
linuxPreflight() {
  # The distribution floor. Without this an Ubuntu 22.04 user gets a clean
  # install, a verified digest, a cheerful "Installed Notary", and then
  # `version GLIBC_2.38 not found` the first time they open it. For an app that
  # holds a key, "it will not start" should never be something you discover
  # after trusting it with one.
  #
  # The toolkit's Linux host declares a GTK floor of 4.10, and the release
  # binaries are built on Ubuntu 24.04. Both land on the same generation:
  # Ubuntu 23.10+, Debian 13+, Fedora 39+. glibc is the proxy for that
  # DISTRIBUTION GENERATION, not a statement about these binaries. Notary's own
  # two binaries need only glibc 2.36; what needs a newer system is GTK 4.10,
  # and there is no way to read GTK's minor version without a -dev package.
  # Every distribution carrying glibc 2.38 carries GTK 4.10, so this reads the
  # one that is always legible and gates on it.
  local glibc
  glibc="$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+$' || true)"
  if [ -n "$glibc" ]; then
    local major minor
    major="${glibc%%.*}"
    minor="${glibc##*.}"
    if [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 38 ]; }; then
      die "this build needs GTK 4.10 or newer, which means a system newer than yours (glibc $glibc).
       That means Ubuntu 23.10+, Debian 13+, or Fedora 39+. Ubuntu 22.04 and
       Debian 12 are too old for it. Building from source on your own system
       works if its GTK is 4.10 or newer: https://github.com/$repo#build"
    fi
  fi

  # GTK 4 itself, AFTER the floor above. The order matters: an Ubuntu 22.04 user
  # has GTK 4.6, so a GTK-presence check passes and then tells them nothing,
  # while the floor tells them the true reason their machine cannot run this.
  # Checked by loader rather than by package name, because the package is called
  # libgtk-4-1 on Debian and Ubuntu, gtk4 on Fedora and Arch, and something else
  # again elsewhere.
  case "$(gtkStatus)" in
    missing) die "GTK 4 is missing. Install it first: apt install libgtk-4-1, dnf install gtk4, or pacman -S gtk4." ;;
    unknown) warn "could not tell whether GTK 4 is installed on this system. If Notary does not open, that is the first thing to check." ;;
  esac
}

# All work happens inside main(), invoked on the very last line, so bash runs
# nothing until the whole script has been read. A truncated `curl | bash` (a
# connection dropped mid-stream) then does nothing at all rather than half of
# an install.
main() {
  # A file already on disk, instead of a published release. For installing
  # without a network, and for trying a build before it is a release.
  local archive="" version=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --archive)
        [ $# -ge 2 ] || die "--archive needs a path."
        archive="$2"
        shift 2
        ;;
      --version)
        [ $# -ge 2 ] || die "--version needs a release tag, for example v0.11.2."
        version="$2"
        shift 2
        ;;
      --prefix)
        [ $# -ge 2 ] || die "--prefix needs a directory."
        opt_prefix="$2"
        shift 2
        ;;
      --no-open)
        opt_no_open=1
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
  done
  [ -z "$archive" ] || [ -z "$version" ] || die "pass --archive or --version, not both."
  if [ -n "$version" ]; then
    # It becomes part of a URL, so only what a release tag can contain.
    case "$version" in
      *[!0-9A-Za-z.-]* | "") die "$version is not a release tag (for example v0.11.2)." ;;
    esac
  fi

  # --- which system ----------------------------------------------------------
  local os arch platform label
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin)
      [ "$arch" = "arm64" ] || die "Notary ships for Apple Silicon (arm64) only. On an Intel Mac, build from source: https://github.com/$repo#build"
      platform="macos"
      label="macOS"
      ;;
    Linux)
      case "$arch" in
        x86_64 | aarch64) ;;
        *) die "no build for $arch. Notary publishes x86_64 and aarch64; build from source for anything else: https://github.com/$repo#build" ;;
      esac
      platform="linux"
      label="$arch"
      ;;
    *) die "Notary publishes builds for macOS (Apple Silicon) and Linux (x86_64 and aarch64), not for $os. Build from source instead: https://github.com/$repo#build" ;;
  esac

  # Only what the chosen path actually uses. `curl` belongs to the download,
  # and demanding it for `--archive` refuses an offline install for a tool that
  # install would never call.
  local tool tools
  if [ "$platform" = "macos" ]; then tools="shasum ditto xattr"; else tools="sha256sum tar"; fi
  [ -n "$archive" ] || tools="curl $tools"
  for tool in $tools; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required and is not on PATH."
  done

  if [ "$platform" = "linux" ]; then linuxPreflight; fi

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
    # Checked when it is there, and then it has to match: a release file and
    # its .sha256 downloaded by hand are verified exactly as a download is.
    if [ -f "$archive.sha256" ]; then
      verify "$tmp/$asset" "$archive.sha256" "$asset"
    else
      warn "no $asset.sha256 beside it, so it is installed as given, unverified."
    fi
  else
    local json=""
    if [ -n "$version" ]; then
      tag="v${version#v}"
      say "Installing the $tag release."
    else
      say "Finding the latest Notary release..."
      local api resp code
      api="https://api.github.com/repos/$repo/releases/latest"
      # Not `curl -f`: -f collapses every HTTP answer into one exit code, so a
      # rate limit and a network failure become the same unhelpful message. The
      # status comes back on its own line instead.
      #
      # A GH_TOKEN in the environment is sent along, which lifts the 60 calls an
      # hour GitHub allows an address without one (a shared CI runner can use
      # that up on its own). It goes in through curl's stdin rather than its
      # arguments, so it never shows in the process list.
      if [ -n "${GH_TOKEN:-}" ]; then
        resp="$(printf 'header = "Authorization: Bearer %s"\n' "$GH_TOKEN" | curl -sSL -K - -w '\n%{http_code}' "$api")" ||
          die "could not reach GitHub. Check your connection and try again."
      else
        resp="$(curl -sSL -w '\n%{http_code}' "$api")" || die "could not reach GitHub. Check your connection and try again."
      fi
      code="$(printf '%s' "$resp" | tail -1)"
      json="$(printf '%s' "$resp" | sed '$d')"
      case "$code" in
        200) ;;
        401) die "GitHub refused the token in GH_TOKEN. Unset GH_TOKEN and run this again." ;;
        403 | 429) die "GitHub rate-limited this machine. Wait a few minutes, name a release with --version, or download the release by hand and pass --archive." ;;
        404) die "no published release found for $repo." ;;
        *) die "GitHub answered $code." ;;
      esac
      tag="$(printf '%s' "$json" | grep -o '"tag_name":[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
      [ -n "$tag" ] || die "could not read the release tag."
      say "Latest release: $tag"
    fi

    # The file name follows from the tag and the system, so `--version` needs no
    # API call at all.
    if [ "$platform" = "macos" ]; then
      asset="Notary-$tag-macos.zip"
    else
      asset="notary-${tag#v}-linux-$arch.tar.gz"
    fi
    if [ -n "$json" ]; then
      # A `case`, not `grep -q`, for the SIGPIPE reason given above gtkStatus.
      case "$json" in
        *"/$tag/$asset\""*) ;;
        *) die "no $label build found on the latest release ($tag)." ;;
      esac
    fi

    local url="https://github.com/$repo/releases/download/$tag/$asset"
    say "Downloading $asset..."
    curl -fSL --progress-bar -o "$tmp/$asset" "$url" || die "download failed. There may be no $label build for $tag."

    # The digest is the file published beside the download, `<file>.sha256`,
    # fetched by the download's own name. It is not read out of the API body:
    # a release whose notes were edited cannot change what this compares
    # against, and there is no list of digests to pick the wrong one from. The
    # macOS installer once took the first digest in the release JSON, which
    # belonged to whichever asset uploaded first, and at v0.10.11 that was a
    # Linux tarball, so every macOS install called a good download corrupt.
    #
    # Required, not best-effort. Verification that warns and installs anyway
    # when the sidecar cannot be fetched is switched off by any transient
    # failure. On an app that holds a key that is not a trade-off worth making:
    # every published release has a digest, so a missing one is a reason to
    # stop.
    curl -fsSL --retry 2 --retry-all-errors -o "$tmp/$asset.sha256" "$url.sha256" 2>/dev/null ||
      die "could not fetch the published SHA-256 for $asset, so the download cannot be verified. Not installing it.
       Try again, or download the file and its .sha256 by hand and pass --archive."
    verify "$tmp/$asset" "$tmp/$asset.sha256" "$asset"
  fi

  if [ "$platform" = "macos" ]; then
    installMacos "$tmp" "$asset"
  else
    installLinux "$tmp" "$asset" "$tag"
  fi
}

# --- macOS -------------------------------------------------------------------
installMacos() {
  local tmp="$1" asset="$2" app="Notary.app"
  say "Unpacking..."
  ditto -x -k "$tmp/$asset" "$tmp/unpack" || die "could not unzip the download."
  local src="$tmp/unpack/$app"
  [ -d "$src" ] || die "the download did not contain $app."

  # --- choose an install location we can actually write to -----------------
  local dest
  if [ -n "$opt_prefix" ]; then
    dest="$opt_prefix"
    mkdir -p "$dest" || die "could not create $dest."
  elif [ -w "/Applications" ] || { [ ! -e "/Applications/$app" ] && mkdir -p "/Applications" 2>/dev/null && [ -w "/Applications" ]; }; then
    dest="/Applications"
  else
    dest="$HOME/Applications"
    mkdir -p "$dest"
  fi
  [ -n "$dest" ] || die "could not determine an install location."

  # Notary stays in the menu bar after its window is closed, so an upgrade
  # usually finds it running. Replacing the bundle under it leaves the old
  # version running, and `open` then brings THAT one forward, so the install
  # looks done and is not. Nothing has changed yet at this point, so stopping
  # here costs a rerun and nothing else.
  if pgrep -f "$dest/$app/Contents/MacOS/" >/dev/null 2>&1; then
    die "Notary is running from $dest/$app. Choose Quit Notary in its menu bar first, then run this again."
  fi

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
  if [ "$opt_no_open" = "1" ]; then
    say "Open it from $dest/$app whenever you're ready."
    return
  fi
  say "Opening Notary. Closing its window leaves it running in the menu bar; choose Quit Notary there to stop it."
  open "$dest/$app" || say "Open it from $dest/$app whenever you're ready."
}

# --- Linux -------------------------------------------------------------------
# Unpacks a tarball and installs it. Shared by the download path and by
# `--archive`, so a local install and a released one are the same install.
installLinux() {
  local tmp="$1" asset="$2" tag="$3"
  say "Unpacking..."
  tar -C "$tmp" -xzf "$tmp/$asset" 2>/dev/null ||
    die "the archive could not be unpacked. The download may be incomplete, or the file passed to --archive may not be a Notary tarball."
  local src
  src="$(find "$tmp" -maxdepth 1 -type d -name 'notary-*-linux-*' | head -1)"
  [ -n "$src" ] || die "the archive did not contain what was expected."
  local required
  for required in notary signer; do
    [ -x "$src/bin/$required" ] || die "$required is missing from the archive."
  done

  # ~/.local, so nothing needs root and nothing lands outside the home
  # directory. This is where the XDG spec puts a single user's own programs, and
  # it is what makes uninstalling "delete three paths".
  local prefix="${opt_prefix:-$HOME/.local}"
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

  if [ "$tag" = "local" ]; then
    say "Installed Notary from $asset."
  else
    say "Installed Notary $tag."
  fi
  if [ "$opt_no_open" = "1" ]; then
    say "Start it from your launcher, or run $prefix/bin/notary, whenever you're ready."
    return
  fi

  # Started with its output kept, briefly. It used to go to /dev/null, so a
  # first run that died on a missing library was indistinguishable from a
  # working install: the script said "Starting it...", nothing appeared, and
  # nothing anywhere said why. On the app that holds your key, that silence is
  # the worst possible failure mode. If it is still alive a moment later the log
  # is dropped and it is left to run.
  say "Starting it..."
  local log pid
  log="$tmp/first-run.log"
  "$prefix/bin/notary" >"$log" 2>&1 &
  pid=$!
  disown 2>/dev/null || true
  sleep 2
  kill -0 "$pid" 2>/dev/null && return
  warn "Notary exited immediately. It is installed at $prefix/bin/notary. This is what it said:"
  sed 's/^/       /' "$log" >&2 || true
}

main "$@"
