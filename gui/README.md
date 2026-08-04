# Notary, the GUI

**Notary**: a native desktop app that approves or denies Nostr
signing requests from your [signer daemon](../daemon).

> **Status: early / work in progress.** This is the interactive front end for
> the headless signer daemon. It walks you through first-run key setup (create
> or import), unlocks the key on later launches, then shows each pending signing
> request and sends back your approve/deny decision, and spawns and supervises
> the daemon itself. `scripts/package-macos.sh` bundles both into a single
> `.app`, shipped as ad-hoc-signed macOS releases (not notarized, see the
> top-level [Install](../README.md#install)).

![Notary: first-run key setup, then approving a live signing request](assets/demo.gif)

<sub>First-run key setup, then the serving screen, the `bunker://` connection URL
to copy into a client, live per-relay status, and approving a real NIP-46 signing
request. The key is generated and held by the signer daemon. It never enters this
app.</sub>

## Architecture

The signer is split into two processes on purpose:

- The **daemon** ([`daemon/`](../daemon))
  holds the secret key, connects to your relays, and does all Nostr work. In
  GUI mode it holds each request for approval and serves a **loopback-only**
  HTTP API.
- **This app** is a separate process that polls that API, shows each pending
  request, and sends back your approve/deny decision.

The key never enters this process. It only ever sees request metadata and
returns a yes/no. Built with the
[Native SDK](https://github.com/vercel-labs/native): declarative markup plus
Zig, rendered natively (no WebView, no Electron).

## Build

Requires [Zig](https://ziglang.org) 0.16.0 and the Native SDK CLI
(`npm install -g @native-sdk/cli`).

```sh
native dev      # build and run with hot reload
native test     # run the headless logic tests
native build    # produce a binary in zig-out/bin/
native check    # validate src/app.native + app.zon
```

## Connect to a signer

Run the daemon in **GUI mode** (see the signer's
[interactive approval](../daemon)
section) so it serves the loopback approval API, then point this app at it
with two environment variables:

- `SIGNER_APPROVAL_HTTP`: the daemon's approval address (default
  `127.0.0.1:8787`).
- `SIGNER_APPROVAL_TOKEN_FILE`: the bearer-token file the daemon wrote
  (default `$HOME/.zig-nostr-signer.token`).

```sh
SIGNER_APPROVAL_HTTP=127.0.0.1:8787 \
SIGNER_APPROVAL_TOKEN_FILE="$HOME/.zig-nostr-signer.token" \
  native dev
```

The app polls the queue (a long-poll chain, so it updates within a second of
a change), renders each pending request, and sends your decision back over
`POST /decision`. The bearer token authenticates every call; the secret key
stays in the daemon.

### First-run key setup

The first time it connects to a daemon that has no key yet, the app shows a
**setup screen**: create a fresh key, or import an existing one (`nsec1…` or
64-char hex), protected by a passphrase. On later launches the daemon comes up
locked and the app shows an **unlock screen** for that passphrase. The key is
generated and decrypted inside the daemon (over `POST /setup` and
`POST /unlock`): the app only ever sends the passphrase, and on import the
secret you type, never a derived key.

### Managed mode (the app supervises the daemon)

A packaged app is self-contained: the `.app` ships the `signer` daemon beside
the GUI in `Contents/MacOS`, and at launch the GUI discovers that sibling and
spawns it, one launch brings up both, no configuration. In development you get
the same one-launch behavior without packaging by pointing `SIGNER_BIN` at a
built daemon (it takes precedence over any bundled one):

```sh
SIGNER_BIN="$(which signer)" \
SIGNER_SECRET_KEY=<64-char hex, dev only, prefer SIGNER_KEY_FILE + SIGNER_PASSPHRASE> \
SIGNER_RELAYS="wss://relay.example.com" \
SIGNER_APPROVAL_HTTP=127.0.0.1:8787 \
SIGNER_APPROVAL_TOKEN_FILE="$HOME/.zig-nostr-signer.token" \
  native dev
```

Either way the daemon child inherits this process's environment (so it gets its
key and relay config), the app waits for it to write its token and then
connects, and if the daemon exits the app shows **Signer stopped** with a
**Restart** button. When the app quits, the daemon child is stopped with it, so
none is left orphaned holding the approval port. The key still only ever lives
in the daemon child.

## Packaging

`scripts/package-macos.sh` produces a single, self-contained
`Notary.app` with both executables side by side in `Contents/MacOS`
(`notary` and `signer`), so one download brings up both:

```sh
# builds the GUI, packages the .app, injects the daemon, and ad-hoc signs it
scripts/package-macos.sh --signer path/to/signer
```

The daemon comes from the [`daemon/`](../daemon) package in this repo; build it
(`cd ../daemon && zig build -Doptimize=ReleaseFast`) and the script finds
`../daemon/zig-out/bin/signer` on its own, or pass `--signer <path>`.

Ad-hoc signing (the default) is what releases ship: the release workflow
([`.github/workflows/release.yml`](../.github/workflows/release.yml)) runs this
on every version tag and attaches the zipped `.app`. Ad-hoc bundles aren't
notarized, so macOS quarantines the download; the
[one-line installer](../README.md#install) clears that flag on install (or do it
by hand with `xattr -dr com.apple.quarantine`).

Notarizing is deliberately out of scope (a WIP key-holder gains little over a
build you can reproduce yourself), but the Developer-ID path is still available
if you want a Gatekeeper-friendly build with your own Apple credentials:

```sh
scripts/package-macos.sh --signing identity \
  --identity "Developer ID Application: Your Name (TEAMID)"
```

## Roadmap

- [x] App scaffold (native window, shell view, logic tests)
- [x] Approval queue over the daemon's loopback API (poll, approve, deny)
- [x] Supervise the daemon as a child process (one launch, key stays isolated)
- [x] Bundle the daemon into the app, one `.app`, discovered and supervised
- [x] First-run key onboarding in-app (create / import / unlock)
- [x] Ad-hoc signed macOS releases + one-line installer (CI on tag; clears quarantine on install)

## License

MIT © Sepehr Safari
