#!/usr/bin/env bash
#
# Regenerate the README/website screenshots from the real app.
#
# Every image under gui/assets/shots/ is rendered by Notary itself: the
# automation build draws its actual canvas to a PNG at 2x, so what ships in the
# README is the app, not a mockup of it. Re-run this after any UI change and
# commit whatever moves; a diff here is a real visual regression.
#
# The signer daemon is replaced by scripts/shots/stub-signer.py, which serves
# the same loopback API from fixed bytes. So this touches no key, no relay and
# no network, and two runs a week apart produce identical pixels.
#
#   scripts/shots.sh          # every shot
#   scripts/shots.sh serving  # just one, while iterating on that screen
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../gui" && pwd)"
OUT="$ROOT/assets/shots"
SNAP_DIR="$ROOT/.zig-cache/native-sdk-automation"
WORK="$(mktemp -d)"
PORT="${SHOTS_STUB_PORT:-8787}"
SCENE_FILE="$WORK/scene"
STUB_PID=""
APP_PID=""

# Canonical window. Fixed here rather than left to app.zon so a shot's
# dimensions never drift with the default window size; 2x for retina.
WIDTH=460
HEIGHT=560
SCALE=2

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarn\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mfail\033[0m %s\n' "$*" >&2; exit 1; }

stop_app() {
  [ -n "$APP_PID" ] || return 0
  kill "$APP_PID" 2>/dev/null || true
  wait "$APP_PID" 2>/dev/null || true
  APP_PID=""
}

cleanup() {
  stop_app
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v native >/dev/null || die "the Native SDK CLI is missing: npm install -g @native-sdk/cli"

# Each scene is "<name>:<pattern>": the pattern is a regex that must appear in
# the automation snapshot before the shutter fires. Without it we would race the
# app's first poll and photograph a half-populated screen.
SCENES=(
  "setup:Set up your signer"
  "unlock:Unlock your signer"
  "serving:Bunker URL"
  "request:sign_event"
)

want="${1:-all}"

say "Building the automation binary..."
(cd "$ROOT" && native build --yes -Doptimize=ReleaseFast -Dautomation=true) \
  >"$WORK/build.log" 2>&1 || { cat "$WORK/build.log" >&2; die "build failed"; }

# The GUI reads its bearer token from a file. The stub accepts anything; the
# file just has to exist, or the app never leaves the connecting state.
echo "screenshot-token" >"$WORK/token"
echo "serving" >"$SCENE_FILE"

say "Starting the stub signer on 127.0.0.1:$PORT..."
SHOTS_SCENE_FILE="$SCENE_FILE" SHOTS_STUB_PORT="$PORT" \
  python3 "$ROOT/../scripts/shots/stub-signer.py" >"$WORK/stub.log" 2>&1 &
STUB_PID=$!
disown "$STUB_PID" 2>/dev/null || true  # else the shell prints "Terminated" over the summary
for _ in $(seq 1 50); do
  grep -q serving "$WORK/stub.log" 2>/dev/null && break
  sleep 0.1
done
grep -q serving "$WORK/stub.log" 2>/dev/null \
  || { cat "$WORK/stub.log" >&2; die "the stub signer did not come up"; }

mkdir -p "$OUT" "$WORK/home"
shot_count=0

for entry in "${SCENES[@]}"; do
  name="${entry%%:*}"
  pattern="${entry#*:}"
  [ "$want" = "all" ] || [ "$want" = "$name" ] || continue

  # One app process per scene. The GUI's phase is decided by the first /info it
  # sees and does not walk backwards out of `connected`, so a shot of the setup
  # screen has to be a launch that finds no key. Restarting is also what keeps
  # the scenes independent: any order, any subset, same pixels.
  echo "$name" >"$SCENE_FILE"
  stop_app
  rm -rf "$SNAP_DIR"

  # A HOME of our own: a screenshot run must never read or write the real one.
  # SIGNER_BIN is deliberately unset so the GUI does not spawn a daemon; with no
  # bundled `signer` beside the binary it stays a pure client of the stub.
  (
    cd "$ROOT" && \
    HOME="$WORK/home" \
    SIGNER_APPROVAL_HTTP="127.0.0.1:$PORT" \
    SIGNER_APPROVAL_TOKEN_FILE="$WORK/token" \
    exec ./zig-out/bin/notary >"$WORK/app-$name.log" 2>&1
  ) &
  APP_PID=$!

  if ! (cd "$ROOT" && native automate wait --timeout 90 >/dev/null 2>&1); then
    warn "$name: the app never reported ready"
    continue
  fi

  (cd "$ROOT" && native automate resize "$WIDTH" "$HEIGHT" "$SCALE" >/dev/null 2>&1) \
    || warn "$name: resize failed, using the default window size"

  if ! (cd "$ROOT" && native automate assert --timeout-ms 30000 "$pattern" >/dev/null 2>&1); then
    warn "$name: never showed \"$pattern\", skipping"
    continue
  fi

  if ! (cd "$ROOT" && native automate screenshot main-canvas "$SCALE" >/dev/null 2>&1); then
    warn "$name: screenshot failed"
    continue
  fi

  src="$SNAP_DIR/screenshot-main-canvas.png"
  [ -f "$src" ] || { warn "$name: no PNG was written"; continue; }
  mv "$src" "$OUT/$name.png"

  # The renderer emits full RGBA; re-encoding drops it to a fraction of the size
  # with no visible change, which matters for a file the README inlines.
  if command -v sips >/dev/null; then
    sips -s format png "$OUT/$name.png" --out "$OUT/$name.png" >/dev/null 2>&1 || true
  fi

  say "$name -> assets/shots/$name.png ($(du -h "$OUT/$name.png" | cut -f1 | tr -d ' '))"
  shot_count=$((shot_count + 1))
done

stop_app
[ "$shot_count" -gt 0 ] || die "no screenshots were produced"
say "Done: $shot_count shot(s) in gui/assets/shots/"
