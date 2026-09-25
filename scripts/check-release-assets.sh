#!/usr/bin/env bash
# Whether a release carries every artifact it is supposed to, before anybody
# can see it.
#
#   gh release view <tag> --json assets \
#     --jq '.assets[] | "\(.name)\t\(.state)\t\(.size)"' \
#     | scripts/check-release-assets.sh <tag>
#   scripts/check-release-assets.sh --self-test
#
# Reads one asset per line (name, state, size, tab separated) and exits 1,
# naming each one that is missing, when the release lacks any artifact a
# release of <tag> should carry. An asset counts only when GitHub says it
# finished uploading and it is not empty: an upload that dies halfway leaves an
# entry with the right name and nothing behind it.
#
# The release workflow runs this before it lifts the draft, which is the check
# its `publish` job used to claim and did not make.
set -euo pipefail

# The Linux architectures release.yml builds. The self-test compares this with
# that workflow's matrix, so the two cannot drift apart unnoticed.
LINUX_ARCHES="x86_64 aarch64"

# Every file a release of $1 should carry, one per line.
expected() {
  local tag="$1" ver="${1#v}" arch
  printf '%s\n' "Notary-$tag-macos.zip" "Notary-$tag-macos.zip.sha256"
  for arch in $LINUX_ARCHES; do
    printf '%s\n' "notary-$ver-linux-$arch.tar.gz" "notary-$ver-linux-$arch.tar.gz.sha256"
  done
}

# Checks the asset lines on stdin against what $1 should carry.
check() {
  local tag="$1" have name missing=0
  have="$(awk -F '\t' '$2 == "uploaded" && $3 > 0 { print $1 }')"
  while IFS= read -r name; do
    # A here-string, not a pipe: `grep -q` stops reading at the first match,
    # and under pipefail the writer's SIGPIPE would turn a match into a miss.
    if ! grep -qxF -- "$name" <<<"$have"; then
      echo "missing: $name" >&2
      missing=1
    fi
  done < <(expected "$tag")
  if [ "$missing" != 0 ]; then
    echo "$tag is not ready to publish. It has:" >&2
    printf '%s\n' "${have:-  (nothing uploaded)}" >&2
    return 1
  fi
  echo "$tag carries all $(expected "$tag" | wc -l | tr -d ' ') artifacts"
}

# Asserts that the asset lines in $4 are refused, and refused for the right
# reason: exactly $3 files reported missing, $2 among them. Checking only that
# the check failed would pass on a fixture that broke the wrong line.
refuses() {
  local what="$1" name="$2" count="$3" err
  if err="$(check v9.9.9 <<<"$4" 2>&1 >/dev/null)"; then
    echo "$what was accepted" >&2; exit 1
  fi
  if ! grep -qxF -- "missing: $name" <<<"$err" ||
    [ "$(grep -c '^missing: ' <<<"$err")" != "$count" ]; then
    echo "$what was refused, but not for the reason expected:" >&2
    printf '%s\n' "$err" >&2
    exit 1
  fi
  echo "ok: $what is refused"
}

self_test() {
  local here full
  here="$(cd "$(dirname "$0")/.." && pwd)"
  full="$(expected v9.9.9 | awk '{ printf "%s\tuploaded\t1000\n", $0 }')"

  check v9.9.9 <<<"$full" >/dev/null ||
    { echo "a complete release was refused" >&2; exit 1; }
  echo "ok: a complete release passes"

  local tab=$'\t'
  refuses "a missing file" "notary-9.9.9-linux-aarch64.tar.gz.sha256" 1 \
    "$(grep -v 'aarch64.tar.gz.sha256' <<<"$full")"
  # The pattern and replacement live in variables: quotes written inside
  # ${var/pattern/replacement} are kept as literal characters, which renamed the
  # file in this fixture and made it fail for the wrong reason.
  local from to
  from="Notary-v9.9.9-macos.zip${tab}uploaded" to="Notary-v9.9.9-macos.zip${tab}starter"
  refuses "an unfinished upload" "Notary-v9.9.9-macos.zip" 1 "${full/$from/$to}"
  from="x86_64.tar.gz${tab}uploaded${tab}1000" to="x86_64.tar.gz${tab}uploaded${tab}0"
  refuses "an empty file" "notary-9.9.9-linux-x86_64.tar.gz" 1 "${full/$from/$to}"
  refuses "a macOS zip without its digest" "Notary-v9.9.9-macos.zip.sha256" 1 \
    "$(grep -v 'macos.zip.sha256' <<<"$full")"
  refuses "a release built for another version" "Notary-v9.9.9-macos.zip" 6 \
    "${full//9.9.9/9.9.8}"

  local matrix
  matrix="$(grep -o 'arch: [a-z0-9_]*' "$here/.github/workflows/release.yml" | cut -d' ' -f2 | sort | tr '\n' ' ')"
  if [ "$matrix" != "$(tr ' ' '\n' <<<"$LINUX_ARCHES" | grep . | sort | tr '\n' ' ')" ]; then
    echo "release.yml builds [$matrix] but this checks [$LINUX_ARCHES]" >&2; exit 1
  fi
  echo "ok: the architectures match release.yml's matrix"
}

case "${1:-}" in
  --self-test) self_test ;;
  "") echo "usage: $0 <tag> < assets, or $0 --self-test" >&2; exit 2 ;;
  *) check "$1" ;;
esac
