#!/bin/bash
# The one-line installer, end to end, on the system this runs on.
#
#   scripts/check-installer.sh
#
# CI runs it on macOS and on Linux. It can be run by hand too: everything it
# installs goes into a temporary directory with --no-open, so it never touches
# /Applications or ~/.local, and never opens, starts or stops a Notary.
#
# 1. install.sh and both old addresses are pure ASCII and parse.
# 2. A system or architecture without a build is refused with a plain message.
# 3. The newest published release installs, and the signer it installed runs.
# 4. A release file with its genuine .sha256 installs; one changed byte, or an
#    empty .sha256, is refused and installs nothing.
# 5. install-macos.sh and install-linux.sh pass their arguments through to
#    install.sh, both from a checkout and piped the way `curl | bash` runs them.
# 6. On macOS, a Notary running from the destination is not replaced.
#
# A GH_TOKEN in the environment is used for the GitHub API, here and by the
# installer, because a shared runner can use up the 60 calls an hour GitHub
# allows an address without one.
set -euo pipefail

repo="zig-nostr/notary"
root="$(cd "$(dirname "$0")/.." && pwd)"
installer="$root/scripts/install.sh"

# The bash that `curl | bash` meets on macOS is /bin/bash, 3.2, so that is the
# one used there, even where a newer bash comes first on PATH (a CI runner has
# one).
b=bash
if [ "$(uname -s)" = "Darwin" ]; then b=/bin/bash; fi

t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  [ -z "${2:-}" ] || printf '%s\n' "$2" | sed 's/^/  | /' >&2
  exit 1
}
ok() { printf 'ok: %s\n' "$1"; }

# --- 1. ASCII and parse --------------------------------------------------------
# macOS runs these with bash 3.2, where a multibyte character next to a
# $variable under `set -u` aborts the script before it has said anything. `tr`
# with LC_ALL=C counts bytes, not characters, on both systems.
for f in install.sh install-macos.sh install-linux.sh; do
  n="$(LC_ALL=C tr -d '\000-\177' <"$root/scripts/$f" | wc -c | tr -d ' ')"
  [ "$n" = "0" ] || fail "scripts/$f carries $n bytes outside ASCII"
  "$b" -n "$root/scripts/$f" || fail "scripts/$f does not parse"
done
ok "the installers are ASCII and parse"

out="$("$b" "$installer" --help 2>&1)" || fail "--help failed" "$out"
case "$out" in *"usage: install.sh"*) ;; *) fail "--help printed no usage" "$out" ;; esac
if out="$("$b" "$installer" --bogus 2>&1)"; then fail "an unknown argument was accepted" "$out"; fi
if out="$("$b" "$installer" --archive x --version v1 2>&1)"; then fail "--archive with --version was accepted" "$out"; fi
ok "the options parse"

# --- 2. no build for this system ---------------------------------------------------
# A fake `uname` first on PATH. These are refused before anything is fetched.
mkdir -p "$t/shim"
for sys in "FreeBSD amd64|not for FreeBSD" "Darwin x86_64|Apple Silicon (arm64) only" "Linux riscv64|no build for riscv64"; do
  want="${sys#*|}"
  # shellcheck disable=SC2086 # split into the system and the architecture
  set -- ${sys%|*}
  # shellcheck disable=SC2016 # the shim's own $1, written literally
  printf '#!/bin/sh\n[ "$1" = "-m" ] && echo %s || echo %s\n' "$2" "$1" >"$t/shim/uname"
  chmod +x "$t/shim/uname"
  if out="$(PATH="$t/shim:$PATH" "$b" "$installer" --no-open 2>&1)"; then
    fail "$1 $2 was not refused" "$out"
  fi
  case "$out" in *"$want"*) ;; *) fail "$1 $2 was refused without saying \"$want\"" "$out" ;; esac
done
ok "a system without a build is refused with a plain message"

# --- 3. the newest published release ------------------------------------------------
api() {
  if [ -n "${GH_TOKEN:-}" ]; then
    printf 'header = "Authorization: Bearer %s"\n' "$GH_TOKEN" | curl -fsSL -K - "$1"
  else
    curl -fsSL "$1"
  fi
}
latest="$(api "https://api.github.com/repos/$repo/releases/latest" | grep -o '"tag_name":[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/' || true)"
[ -n "$latest" ] || fail "could not read the latest release tag"

case "$(uname -s)" in
  Darwin) asset="Notary-$latest-macos.zip" ;;
  Linux) asset="notary-${latest#v}-linux-$(uname -m).tar.gz" ;;
  *) fail "this check runs on macOS and Linux" ;;
esac

# Where an install under a prefix puts the signer, and a check that the rest of
# it is there.
installed() {
  case "$(uname -s)" in
    Darwin)
      [ -d "$1/Notary.app" ] || fail "no Notary.app in $1"
      [ -x "$1/Notary.app/Contents/MacOS/notary" ] || fail "no window binary in $1/Notary.app"
      printf '%s\n' "$1/Notary.app/Contents/MacOS/signer"
      ;;
    Linux)
      [ -x "$1/bin/notary" ] || fail "no notary in $1/bin"
      grep -qxF "Exec=\"$1/bin/notary\"" "$1/share/applications/notary.desktop" ||
        fail "the desktop entry does not point at $1/bin/notary" "$(cat "$1/share/applications/notary.desktop")"
      printf '%s\n' "$1/bin/signer"
      ;;
  esac
}

out="$("$b" "$installer" --prefix "$t/latest" --no-open 2>&1)" || fail "installing the latest release failed" "$out"
case "$out" in *"Latest release: $latest"*) ;; *) fail "the installer did not report $latest as the latest release" "$out" ;; esac
case "$out" in *"SHA-256 verified."*) ;; *) fail "the installer did not verify the download" "$out" ;; esac
signer="$(installed "$t/latest")"
if [ "$(uname -s)" = "Darwin" ]; then
  v="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$t/latest/Notary.app/Contents/Info.plist")"
  [ "$v" = "${latest#v}" ] || fail "installed Notary.app says $v, the latest release is $latest"
  codesign --verify "$t/latest/Notary.app" || fail "the installed Notary.app does not pass codesign --verify"
fi
# Run with nothing configured, in an empty home, the signer prints its usage and
# exits: proof the installed binary loads and runs here, without a key, a relay
# or a file of anyone's.
mkdir -p "$t/home"
out="$(env -i PATH=/usr/bin:/bin HOME="$t/home" "$signer" 2>&1 || true)"
case "$out" in *"headless NIP-46 remote signer"*) ;; *) fail "the installed signer did not run" "$out" ;; esac
ok "the latest release ($latest) installs, and its signer runs"

# --- 4. the checksum fails closed -----------------------------------------------------
base="https://github.com/$repo/releases/download/$latest"
mkdir -p "$t/genuine" "$t/tampered" "$t/empty"
curl -fsSL -o "$t/genuine/$asset" "$base/$asset" || fail "could not download $asset"
curl -fsSL -o "$t/genuine/$asset.sha256" "$base/$asset.sha256" || fail "could not download $asset.sha256"

out="$("$b" "$installer" --archive "$t/genuine/$asset" --prefix "$t/genuine-install" --no-open 2>&1)" ||
  fail "the genuine release file did not install through --archive" "$out"
case "$out" in *"SHA-256 verified."*) ;; *) fail "--archive did not check the .sha256 beside it" "$out" ;; esac
installed "$t/genuine-install" >/dev/null

# One byte changed in the middle, with the genuine .sha256 beside it.
cp "$t/genuine/$asset" "$t/genuine/$asset.sha256" "$t/tampered/"
size="$(wc -c <"$t/genuine/$asset" | tr -d ' ')"
for byte in X Y; do
  printf '%s' "$byte" | dd of="$t/tampered/$asset" bs=1 seek=$((size / 2)) conv=notrunc 2>/dev/null
  cmp -s "$t/genuine/$asset" "$t/tampered/$asset" || break
done
cmp -s "$t/genuine/$asset" "$t/tampered/$asset" && fail "could not make a tampered copy"
if out="$("$b" "$installer" --archive "$t/tampered/$asset" --prefix "$t/tampered-install" --no-open 2>&1)"; then
  fail "a tampered release file installed" "$out"
fi
case "$out" in *"checksum mismatch"*) ;; *) fail "a tampered release file was refused without saying why" "$out" ;; esac
[ -z "$(ls -A "$t/tampered-install" 2>/dev/null)" ] || fail "a refused install left files in its prefix"

# An empty .sha256 must not compare equal to anything.
cp "$t/genuine/$asset" "$t/empty/"
: >"$t/empty/$asset.sha256"
if out="$("$b" "$installer" --archive "$t/empty/$asset" --prefix "$t/empty-install" --no-open 2>&1)"; then
  fail "a release file with an empty .sha256 installed" "$out"
fi
case "$out" in *"empty or malformed"*) ;; *) fail "an empty .sha256 was refused without saying why" "$out" ;; esac
ok "a changed byte or an empty digest is refused and installs nothing"

# --- 5. the old addresses ---------------------------------------------------------------
for w in install-macos.sh install-linux.sh; do
  out="$("$b" "$root/scripts/$w" --archive "$t/genuine/$asset" --prefix "$t/$w-checkout" --no-open 2>&1)" ||
    fail "scripts/$w from a checkout failed" "$out"
  installed "$t/$w-checkout" >/dev/null
  # Piped, as `curl | bash` runs it: no file beside it, so it fetches
  # install.sh, here the one in this tree rather than the one on main.
  out="$(NOTARY_INSTALLER_URL="file://$installer" "$b" -s -- --archive "$t/genuine/$asset" --prefix "$t/$w-piped" --no-open <"$root/scripts/$w" 2>&1)" ||
    fail "scripts/$w piped into bash failed" "$out"
  installed "$t/$w-piped" >/dev/null
done
ok "install-macos.sh and install-linux.sh run install.sh with their arguments"

# --- 6. a running copy is not replaced (macOS) ---------------------------------------------
# A stand-in process named like the app in a temporary prefix, stopped by its
# own PID afterwards. Nothing else is looked at or touched.
if [ "$(uname -s)" = "Darwin" ]; then
  mkdir -p "$t/running/Notary.app/Contents/MacOS"
  /bin/bash -c "exec -a '$t/running/Notary.app/Contents/MacOS/notary' sleep 30" &
  stand_in=$!
  sleep 1
  if out="$("$b" "$installer" --archive "$t/genuine/$asset" --prefix "$t/running" --no-open 2>&1)"; then
    kill "$stand_in" 2>/dev/null || true
    fail "a running Notary was replaced" "$out"
  fi
  kill "$stand_in" 2>/dev/null || true
  wait "$stand_in" 2>/dev/null || true
  case "$out" in *"Choose Quit Notary"*) ;; *) fail "a running Notary was refused without saying what to do" "$out" ;; esac
  [ ! -e "$t/running/Notary.app/Contents/MacOS/signer" ] || fail "the refused install wrote into the running bundle"
  ok "a running Notary is not replaced"
fi
