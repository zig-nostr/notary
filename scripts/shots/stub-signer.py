#!/usr/bin/env python3
"""A stand-in for the signer daemon's loopback approval API, for screenshots.

The GUI is a pure HTTP client: it learns every on-screen fact from `GET /info`
and `GET /pending`. Serving those two endpoints from a script, instead of
running the real daemon, buys three things the real thing cannot give a
screenshot:

  * determinism. The same bytes every run, so a shot only changes when the UI
    changes, and a diff in `assets/shots/` means someone moved a pixel.
  * no key, no relays, no network. Nothing here signs anything or dials out,
    so the shots can never leak a real pubkey or a real bunker secret.
  * states that are otherwise hard to hold still: a relay mid-connect, a
    request sitting unapproved, all frozen for as long as the camera needs.

The scene is a single word in the file at $SHOTS_SCENE_FILE, re-read on every
request, so the driver flips states by writing to it. See scenes() below.

Not a mock of the daemon's behaviour: it only replays the daemon's wire format
(gui/src/main.zig, parseInfo/parsePending). If those structs change, this
changes with them.
"""

import http.server
import json
import os
import sys
import threading
import time
import urllib.parse

SCENE_FILE = os.environ.get("SHOTS_SCENE_FILE", "")
PORT = int(os.environ.get("SHOTS_STUB_PORT", "8787"))

# A demo identity. Deliberately not a real key: the pubkey is a fixed pattern
# and the bunker secret is the literal word, so nothing here is usable and
# nobody reading the README can mistake it for live credentials.
PUBKEY = "9f2a4c6e8b0d1357ace02468bdf13579" "0e2c4a6890abcdef1234567890abcdef"
RELAYS = [
    ("wss://relay.damus.io", "connected"),
    ("wss://nos.lol", "connected"),
    ("wss://relay.primal.net", "connecting"),
]
BUNKER = (
    f"bunker://{PUBKEY}"
    "?relay=wss://relay.damus.io"
    "&relay=wss://nos.lol"
    "&secret=demo"
)

# created_at is pinned, not "now": a wall-clock timestamp would make the
# rendered row differ between runs even when nothing about the UI changed.
PINNED_CREATED_AT = 1754300000


def scenes():
    """Every screenshot state, as the (info, pending) the GUI would receive.

    `state` picks the screen: "uninitialized" is first-run setup, "locked" is
    the unlock prompt, "unlocked" is the serving screen. `bunker` and `relays`
    only render while unlocked, so the onboarding scenes leave them empty.
    """
    return {
        # First run: no key yet. The GUI shows create-or-import + passphrase.
        "setup": (
            {"state": "uninitialized", "pubkey": "", "bunker": "", "relays": []},
            [],
        ),
        # Returning launch: key on disk, daemon came up locked.
        "unlock": (
            {"state": "locked", "pubkey": PUBKEY, "bunker": "", "relays": []},
            [],
        ),
        # Serving, queue empty. The hero shot: bunker URL to copy, live relays.
        "serving": (
            {
                "state": "unlocked",
                "pubkey": PUBKEY,
                "bunker": BUNKER,
                "relays": [{"url": u, "status": s} for u, s in RELAYS],
            },
            [],
        ),
        # A real signing request waiting on a decision.
        "request": (
            {
                "state": "unlocked",
                "pubkey": PUBKEY,
                "bunker": BUNKER,
                "relays": [{"url": u, "status": s} for u, s in RELAYS],
            },
            [{"id": 1, "method": "sign_event", "kind": 1,
              "created_at": PINNED_CREATED_AT}],
        ),
    }


SCENES = scenes()


def current_scene():
    """The scene named in SCENE_FILE, defaulting to the serving screen.

    Read per request rather than cached: the driver writes this file between
    screenshots, and the GUI is long-polling when it does.
    """
    try:
        with open(SCENE_FILE) as f:
            name = f.read().strip()
    except OSError:
        name = ""
    return SCENES.get(name, SCENES["serving"])


def scene_version():
    """A queue version derived from the scene, so /pending can long-poll.

    The GUI asks for `?since=<version>` and expects the response to be withheld
    until the queue actually differs. Numbering scenes gives us that: flipping
    the scene file bumps the version, which releases the waiting poll.
    """
    names = list(SCENES)
    try:
        with open(SCENE_FILE) as f:
            return names.index(f.read().strip()) + 1
    except (OSError, ValueError):
        return names.index("serving") + 1


class Handler(http.server.BaseHTTPRequestHandler):
    # Quiet: the driver's own output is the log, and one line per long-poll
    # would bury it.
    def log_message(self, *args):
        pass

    def _send(self, payload, code=200):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        info, pending = current_scene()

        if parsed.path == "/info":
            self._send({**info, "timeout_ms": 60000})
            return

        if parsed.path == "/pending":
            qs = urllib.parse.parse_qs(parsed.query)
            since = int(qs.get("since", ["0"])[0])
            # Long-poll: hold until the scene (and so the version) moves on,
            # matching the daemon's contract. Bounded so the GUI's own timeout
            # never wins the race and reconnects mid-shot.
            deadline = time.monotonic() + 20
            while scene_version() <= since and time.monotonic() < deadline:
                time.sleep(0.05)
            _, pending = current_scene()
            self._send({"version": scene_version(), "pending": pending})
            return

        self._send({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        if length:
            self.rfile.read(length)
        parsed = urllib.parse.urlparse(self.path)

        # /setup and /unlock hand back a pubkey; the GUI moves to the serving
        # screen on that alone. /decision just needs to not fail. Nothing here
        # verifies a passphrase: there is no key to protect.
        if parsed.path in ("/setup", "/unlock"):
            self._send({"ok": True, "pubkey": PUBKEY})
            return
        if parsed.path == "/decision":
            self._send({"ok": True})
            return
        self._send({"error": "not found"}, 404)


class Server(http.server.ThreadingHTTPServer):
    # Each long-poll parks a thread; without this the process would refuse to
    # exit while one is still parked.
    daemon_threads = True
    allow_reuse_address = True


def main():
    if not SCENE_FILE:
        print("stub-signer: SHOTS_SCENE_FILE is required", file=sys.stderr)
        return 2
    server = Server(("127.0.0.1", PORT), Handler)
    print(f"stub-signer: serving 127.0.0.1:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
