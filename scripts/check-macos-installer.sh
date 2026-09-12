# The installer verifies the file it downloaded, not whatever is listed first.
#
# Two checks, because they catch different things.
set -eu
repo="$1"
prefix="$2"

extract() { printf '%s' "$1" | tr -d '\n' | tr '{' '\n' | grep 'macos\.zip' | grep -o 'sha256:[0-9a-f]\{64\}' | head -1 | cut -d: -f2 || true; }

# 1. A FIXTURE with a Linux asset first. This is the case that broke, and it
#    breaks deterministically whether or not the live release happens to be
#    ordered that way today. Pretty-printed and carrying an `uploader` object,
#    because the real response is both and a flat fixture would pass against
#    code that cannot read the real thing.
fixture='{
  "tag_name": "v9.9.9",
  "assets": [
    {
      "name": "notary-9.9.9-linux-aarch64.tar.gz",
      "uploader": { "login": "github-actions[bot]", "id": 41898282 },
      "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "browser_download_url": "https://example.com/notary-9.9.9-linux-aarch64.tar.gz"
    },
    {
      "name": "Notary-v9.9.9-macos.zip",
      "uploader": { "login": "github-actions[bot]", "id": 41898282 },
      "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "browser_download_url": "https://example.com/Notary-v9.9.9-macos.zip"
    }
  ]
}'
got="$(extract "$fixture")"
if [ "$got" != "2222222222222222222222222222222222222222222222222222222222222222" ]; then
  echo "With a Linux asset listed first, the installer picks the wrong digest."
  echo "  picked: ${got:-nothing}"
  echo "  wanted: 2222... (the macOS zip)"
  echo "That is the same failure Plaza hit at v0.19.0: a correct download reported as corrupt."
  exit 1
fi
echo "ok: a Linux asset listed first does not steal the macOS digest"

# 2. The LIVE release, because a fixture only encodes what I think the response
#    looks like, and what can break this again is GitHub changing exactly that.
json="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest")"
want="$(printf '%s' "$json" | python3 -c 'import json,sys
d=json.load(sys.stdin)
for a in d.get("assets",[]):
    if a["name"].endswith("macos.zip"):
        print((a.get("digest") or "").replace("sha256:",""))
        break')"
if [ -z "$want" ]; then
  echo "ok: the latest release publishes no macOS digest, nothing to compare"
else
  got="$(extract "$json")"
  if [ "$got" != "$want" ]; then
    echo "Against the live release, the installer picks the wrong digest."
    echo "  picked: ${got:-nothing}"
    echo "  wanted: $want"
    exit 1
  fi
  echo "ok: against the live release the installer picks the macOS digest ($want)"
fi

# 3. And the script that ships is the one these checks describe.
grep -q "tr -d '\\\\n' | tr '{' " "$prefix/scripts/install-macos.sh" || {
  echo "$prefix/scripts/install-macos.sh no longer flattens before splitting."
  exit 1
}
bash -n "$prefix/scripts/install-macos.sh"
echo "ok: the shipped script is the one that was checked"
