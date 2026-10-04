#!/usr/bin/env bash
# The two window manifests agree everywhere except the lines that make the
# macOS app a background resident.
#
#   scripts/check-manifests.sh
#
# gui/app.zon is what the Native SDK tooling reads: it names the version, and on
# macOS it makes the window hide when closed and drops the Dock icon. Linux
# builds read gui/app.linux.zon instead (see gui/build.zig), because the
# toolkit refuses a hiding window there. Every other line has to match, so a
# version bump or a change to the window in one file cannot miss the other.
set -euo pipefail

cd "$(dirname "$0")/../gui"

derived="$(sed \
  -e '/^ *\.dock_visible = false,$/d' \
  -e '/^ *\.close_policy = "hide",$/d' \
  -e 's/, "tray" }/ }/' \
  app.zon)"

if [ "$derived" != "$(cat app.linux.zon)" ]; then
  echo "gui/app.linux.zon has drifted from gui/app.zon." >&2
  echo "It should be app.zon without dock_visible, close_policy and the tray capability:" >&2
  diff <(printf '%s\n' "$derived") app.linux.zon >&2 || true
  exit 1
fi
echo "app.linux.zon matches app.zon"
