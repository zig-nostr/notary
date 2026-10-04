# Notary Architecture

Notary is a native NIP-46 remote signer split into two separate processes. The architecture ensures the secret key stays isolated and under direct user control.

## Two Processes, One Purpose

Notary consists of two processes that communicate exclusively over a loopback HTTP API:

**The Daemon** (`daemon/`, the `signer` binary) is a headless process that:
- Holds the user's secret key (encrypted at rest with NIP-49)
- Connects to Nostr relays and speaks NIP-46 protocol
- Decrypts the key once at startup
- Responds to all signing requests
- Serves an approval API when running in GUI mode

**The GUI** (`gui/`, the `notary` binary) is a Native SDK app that:
- Polls the daemon's approval queue over HTTP
- Shows each pending request to the user
- Sends back the user's decision (allow once, for a day, always, or deny)
- Optionally supervises the daemon as a child process
- Receives only the request metadata; never sees the key

The key never leaves the daemon. It is generated there, decrypted there, used there. The GUI only carries request metadata back and forth.

## Two Daemon Modes

The daemon operates in one of two modes, never both:

**Standalone ("bunker" mode):**
- The daemon runs as a long-lived service on the user's machine or a server
- It connects to real Nostr relays and advertises a `bunker://` connection URL
- Any NIP-46 client, from this machine or another, can connect if they have the URL
- Clients prove their identity via their own keypair; the daemon needs a connection secret to reject fakes
- This is the traditional NIP-46 signer setup

**Embedded ("keyholder" mode):**
- The daemon is started by a parent app (such as Plaza) at launch
- It binds to an ephemeral port on loopback and hands that port only to its parent process, over a pipe
- It connects to no relays; all requests come over that private pipe
- Only the one parent app can reach it; file permissions do not isolate apps on the desktop, so a public port would be reachable by every app you run
- The key cannot be stolen by a different app because that app has no path to reach the signer

## Daemon Modules

`daemon/src/` contains the signer's logic, one Zig module per concern:

**main.zig**: Entry point and configuration. Loads environment variables, decrypts the key (or skips it when booting without one in GUI mode), starts the relay connection loop and the approval HTTP server, and schedules an idle timer to shut down the process when unused.

**approval.zig**: The approval request queue. Holds each pending NIP-46 request sent to the approval API, tracks whether it has been allowed/denied/timed out, and remembers the user's standing decisions (allow forever, for a day, or once per client/kind pair).

**approval_http.zig**: The loopback-only HTTP API. Serves `GET /info` (key state), `POST /setup` (first-run key generation), `POST /unlock` (decrypt the key), `GET /pending` (long-poll the queue), and `POST /decision` (send the user's answer). Validates the bearer token on every request.

**relay_keeper.zig**: Manages connections to each relay. One task per relay; reconnects automatically if a relay drops.

**audit.zig**: Logs every use of the key to a file: who asked (`GET /pending` from which client), what they asked for, and whether they were approved. The file is mode 0600 (readable only by the owner), and writes are held by a mutex so they stay whole.

**onboarding.zig**: Handles the setup flow. Generates a fresh key with a passphrase, or imports an existing `nsec` or hex key. Encrypts it to disk and returns the `bunker://` URL. The key is generated and decrypted inside the daemon; only the passphrase and the import secret cross the HTTP API.

## GUI Structure

`gui/src/` contains the approval window, written in Native SDK (declarative markup plus Zig):

**app.native**: The window's declarative markup. Defines the layout, text, buttons, and state-driven visibility of three screens: the setup screen (create or import a key), the unlock screen (passphrase on later launches), and the approval screen (approve or deny each request).

**main.zig**: The app logic. Maintains the state machine (setup → serving → request approval), polls the daemon's approval queue with a long-poll chain (so the window updates within a second when a new request arrives), sends decisions back over `POST /decision`, and handles daemon supervision. All I/O is async (daemon spawn, HTTP fetch, backoff timers), so the `update` function is a pure state machine and the view stays declarative.

**tests.zig**: Logic tests for the state machine and HTTP handling, run with `native test`.

The window is built with the Native SDK (`native build`) and produces a binary in `zig-out/bin/notary`.

## Daemon Discovery and Supervision

The GUI finds and supervises the daemon:

**In packaged apps** (the macOS `.app` released on GitHub): The daemon binary (`signer`) sits beside the GUI binary (`notary`) in `Contents/MacOS/`. At launch the GUI scans that directory and executes the sibling, inheriting this process's environment (so the daemon gets `SIGNER_KEY_FILE`, `SIGNER_PASSPHRASE`, `SIGNER_RELAYS`, `SIGNER_APPROVAL_HTTP`).

**In development**: Set `SIGNER_BIN` to the full path of the daemon binary (e.g. `daemon/zig-out/bin/signer`), and run `native dev`. The GUI spawns that daemon and supervises it the same way.

**Attached mode**: If the daemon is already running elsewhere, the GUI skips spawning and connects to it via `SIGNER_APPROVAL_HTTP` and `SIGNER_APPROVAL_TOKEN_FILE`.

When the GUI exits, it terminates the daemon child with it, so no process is left orphaned holding the approval port. If the daemon crashes, the GUI shows "Signer stopped" with a "Restart" button.

## NIP-49 Key Storage

The key is encrypted at rest with the NIP-49 standard (scrypt key derivation, XChaCha20-Poly1305 AEAD cipher):

- On first run, the GUI sends a passphrase and optional secret key (for import) to `POST /setup`, and the daemon generates or imports, encrypts, and writes the file.
- The file is stored as `~/.zig-nostr-signer.key` by default (configurable via `SIGNER_KEY_FILE`) with permissions `0600` (readable only by the owner).
- On subsequent launches, the daemon starts locked, the GUI shows an unlock screen, and the user enters the passphrase.
- The daemon decrypts the key in memory using the passphrase sent over `POST /unlock`, never writing it unencrypted to disk.
- When a client connects and requests a signing operation, the decrypted key is used; it is never exported or logged.

The passphrase is required to unlock the key on every launch, so whoever is at the keyboard must know it. Nothing is kept in memory after the app closes.

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

The window depends on `gui/app.zon`, which pins the Native SDK version and declares fonts and other resources.

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
