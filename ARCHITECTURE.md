# Notary Architecture

Notary is a native NIP-46 remote signer split into two separate processes. The architecture ensures the secret key stays isolated and under direct user control.

## Two Processes, One Purpose

Notary consists of two processes that communicate exclusively over a loopback HTTP API:

**The Daemon** (`daemon/`, the `signer` binary) is a headless process that:
- Holds the user's secret key (encrypted at rest with NIP-49)
- Connects to Nostr relays and speaks NIP-46 protocol, when it is serving clients over them
- Decrypts the key once: when the window unlocks it, or at startup when the environment supplies it
- Answers signing requests, holding each one for approval when a window is attached
- Serves an approval API when running in GUI mode

**The GUI** (`gui/`, the `notary` binary) is a Native SDK app that:
- Polls the daemon's approval queue over HTTP
- Shows each pending request to the user
- Sends back the user's decision (allow once, for a day, always, or deny)
- Optionally supervises the daemon as a child process
- Receives only the request metadata, and never holds the key; the import screen forwards a pasted `nsec` to the daemon once and keeps nothing
- On macOS, stays running in the menu bar when its window is closed (see Background Residency)

The key never leaves the daemon. It is generated there, decrypted there, used there. The GUI only carries request metadata back and forth.

## Two Daemon Modes

The daemon operates in one of two modes, never both:

**Standalone ("bunker" mode):**
- The daemon connects to real Nostr relays and advertises a `bunker://` connection URL
- Any NIP-46 client, from this machine or another, can connect if they have the URL
- Clients prove their identity via their own keypair; a connection secret (`SIGNER_CONNECT_SECRET`) is optional, and when set a client must echo it
- Started by Notary's window with relay serving on, each request waits for approval in the window
- Run headless from a terminal with `SIGNER_RELAYS`, there is no window, and requests are answered without asking (behind the connection secret when one is set)
- This is the traditional NIP-46 signer setup

**Embedded ("keyholder" mode):**
- The daemon is started by a parent app (such as Plaza) at launch
- It binds to an ephemeral port on loopback and hands that port only to its parent process, over a pipe
- It connects to no relays unless the reader turns relay serving on in Notary's window; its requests come from the parent app over the loopback channel
- The port is not a name any other app can look up, and the bearer secret for it goes to the daemon on its stdin, so only the parent can authenticate; file permissions do not isolate apps on the desktop, so a credential in a file would be readable by every app you run
- The daemon exits when its parent goes away, which hands the key back

## Daemon Modules

`daemon/src/` contains the signer's logic, one Zig module per concern:

**main.zig**: Entry point and configuration. Loads environment variables, loads the key (or boots without one in GUI mode and waits for the window to set it up or unlock it), starts the approval HTTP server, and runs the relay connections when it is serving over relays. The idle exit is configured here (`SIGNER_IDLE_EXIT_MS`, fifteen minutes by default, `0` to stay up) and enforced by the approval server.

**approval.zig**: The approval request queue. Holds each pending NIP-46 request sent to the approval API, tracks whether it has been allowed, denied or timed out, and records how long each answer stands for a client and method (once, an hour, a day, or always).

**approval_http.zig**: The loopback-only HTTP API. Serves `GET /info` (key state), `POST /setup` (first-run key generation), `POST /unlock` (decrypt the key), `POST /lock`, `POST /forget`, `POST /export` (hand the key back behind the passphrase), `POST /relays` (whether to answer clients over relays), `POST /nostrconnect`, `GET /pending` (long-poll the queue), and `POST /decision` (send the user's answer), plus the local signing protocol an embedding app uses. Checks the bearer token in constant time.

**relay_keeper.zig**: Watches the relay connections for silence. Each relay has its own thread; this one more thread pings and gives up on a connection that has gone quiet so it is dialled again.

**audit.zig**: Logs every use of the key to a file, one JSON line each: what happened (sign, decision, unlock, setup, lock, forget), who asked, the id of what was signed, and how it ended. It never records keys, passphrases or note content. The file is mode 0600 (readable only by the owner), writes go through one lock so they stay whole, and it rolls over at 4 MiB.

**onboarding.zig**: Handles the setup flow. Generates a fresh key with a passphrase, or imports an existing `nsec` or hex key. Encrypts it to disk, and the daemon's `/info` then reports the `bunker://` URL. The key is generated and decrypted inside the daemon; only the passphrase and the import secret cross the HTTP API.

## GUI Structure

`gui/src/` contains the approval window, written in Native SDK (declarative markup plus Zig):

**app.native**: The window's declarative markup. Defines the layout, text, buttons, and state-driven visibility of three screens: the setup screen (create or import a key), the unlock screen (passphrase on later launches), and the approval screen (approve or deny each request).

**main.zig**: The app logic. Maintains the state machine (setup → serving → request approval), polls the daemon's approval queue with a long-poll chain (so the window updates within a second when a new request arrives), sends decisions back over `POST /decision`, and handles daemon supervision. All I/O is async (daemon spawn, HTTP fetch, backoff timers), so the `update` function is a pure state machine and the view stays declarative.

**tests.zig**: Logic tests for the state machine and HTTP handling, run with `native test`.

The window is built with the Native SDK (`native build`) and produces a binary in `zig-out/bin/notary`.

## Background Residency

On macOS the standalone app keeps running when its window is closed, because the signer is only useful if it can answer clients while no window is open.

- `gui/app.zon` declares the window with `close_policy = "hide"`, the app with `dock_visible = false`, and the `tray` capability. Closing the window hides it, a menu bar item stays (`N`, or `N 2` with two requests waiting, with Open Notary and Quit Notary), and there is no Dock icon.
- A request that was not in the previous poll brings the window to the front. If it was away, it goes away again once the queue is empty. A window the reader had open, or opened from the menu, stays until they close it.
- If the signer the app started stops while the window is away, the window comes back and says so.
- Quit Notary ends the app, and the runtime stops the signer child with it. A signer the app only attached to is not its to stop.
- The host reports a hidden window to the runtime but not to the app, so `watchWindow` in `main.zig` wraps the app's event handler and reads the window table after each event to dispatch a `window_hidden` message.

Two cases behave as before. A window another app started with its own keyholder (`--approval-http`, which is how Plaza embeds Notary) has no menu bar item and gets its Dock icon back at boot, and when its window is hidden the process exits, because the parent app learns the window closed only when the process exits. The keyholder belongs to that parent and is unaffected. It also runs a quarter-second timer that only reads the window table, so it exits about as soon as it is closed. And on Linux the toolkit's host has no status item that could bring a hidden window back, so closing the window quits.

Because `app.zon` is the file the host reads for the startup window, Linux builds read `gui/app.linux.zon`, which is `app.zon` without those three lines. `gui/build.zig` picks the file by target and `scripts/check-manifests.sh` fails CI if the two differ anywhere else.

## Daemon Discovery and Supervision

The GUI finds and supervises the daemon:

**In packaged apps** (the macOS `.app` released on GitHub): The daemon binary (`signer`) sits beside the GUI binary (`notary`) in `Contents/MacOS/`. At launch the GUI scans that directory and executes the sibling, inheriting this process's environment (so the daemon gets `SIGNER_KEY_FILE`, `SIGNER_PASSPHRASE`, `SIGNER_RELAYS`, `SIGNER_APPROVAL_HTTP`).

**In development**: Set `SIGNER_BIN` to the full path of the daemon binary (e.g. `daemon/zig-out/bin/signer`), and run `native dev`. The GUI spawns that daemon and supervises it the same way.

**Attached mode**: If the daemon is already running elsewhere, the GUI skips spawning and connects to it via `SIGNER_APPROVAL_HTTP` and `SIGNER_APPROVAL_TOKEN_FILE`.

**Handed a keyholder**: An app that embeds Notary starts the window with `--approval-http <addr>` and the bearer secret on stdin. The window attaches to that keyholder and never starts, stops or replaces one.

When the GUI exits, it terminates the daemon child it started with it, so no process is left orphaned holding the approval port. If that daemon stops, the GUI shows "Signer stopped" with a "Restart signer" button.

## NIP-49 Key Storage

The key is encrypted at rest with the NIP-49 standard (scrypt key derivation, XChaCha20-Poly1305 AEAD cipher):

- On first run, the GUI sends a passphrase and optional secret key (for import) to `POST /setup`, and the daemon generates or imports, encrypts, and writes the file.
- The file is stored as `~/.zig-nostr-signer.key` by default (configurable via `SIGNER_KEY_FILE`) with permissions `0600` (readable only by the owner).
- On subsequent launches, the daemon starts locked, the GUI shows an unlock screen, and the user enters the passphrase.
- The daemon decrypts the key in memory using the passphrase sent over `POST /unlock`, never writing it unencrypted to disk.
- When a client connects and requests a signing operation, the decrypted key is used; it is never logged. It leaves the daemon only through `POST /export`, the backup button, which asks for the passphrase every time.

The passphrase is required to unlock the key on every launch, so whoever is at the keyholder must know it. The daemon exits when the app that started it goes away, or after fifteen minutes with nothing using it, and the decrypted key goes with the process.

## Build and Test

**Daemon** (Zig 0.16.0):

```sh
cd daemon
zig build
zig build test
zig fmt --check .
```

Build produces `zig-out/bin/signer`. Tests include unit tests for approval logic, request validation, and audit logging.

**GUI** (Zig 0.16.0, Native SDK CLI):

```sh
cd gui
native check       # validate markup and manifest
native test        # run logic tests
native build       # produce binary in zig-out/bin/notary
zig fmt --check src
```

The window's manifest is `gui/app.zon` (name, version, permissions, the window); the Native SDK is pinned in `gui/build.zig.zon`. `scripts/check-manifests.sh` checks that `gui/app.linux.zon` still matches it.

**Combined release** (macOS):

```sh
scripts/package-macos.sh --signer path/to/daemon/zig-out/bin/signer
```

Builds the GUI, bundles the daemon into a single `Notary.app`, and ad-hoc signs it. The installer script clears macOS's quarantine flag on install.

The daemon is built separately first, then injected into the app by the packaging script, so either can be updated independently.

## Related Repositories

- [`zig-nostr/nostr`](https://github.com/zig-nostr/nostr): the Nostr protocol library on which the daemon is built
- [`zig-nostr/plaza`](https://github.com/zig-nostr/plaza): the native client that embeds Notary as its keyholder
- [Native SDK](https://github.com/vercel-labs/native): the toolkit used for the GUI
