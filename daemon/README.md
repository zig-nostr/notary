# signer

A headless [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md)
remote signer ("bunker") for Nostr, built on the
[zig-nostr/nostr](https://github.com/zig-nostr/nostr) library.

It keeps your `nsec` on a machine you control and signs on behalf of web and
native clients over a relay, the secret key never reaches the client.

> **Status: early / work in progress.** The current build loads an encrypted
> (NIP-49) key from disk, connects to your relays, and answers NIP-46 requests,
> `get_public_key`, `sign_event`, `ping`, and NIP-44 encrypt/decrypt, behind the
> connection secret and an optional method/event-kind allowlist. It works
> against relays that require NIP-42 authentication. It can also run in **GUI
> mode**: it holds each request for interactive approval over a loopback API,
> and can create or unlock the key on first run from that same API, the key
> never leaves the daemon. The native approval app ships with it: one download
> brings up both.

## Build

Requires [Zig](https://ziglang.org) 0.16.0.

```sh
zig build
```

## Usage

The signer is configured with environment variables. First create an encrypted
key file. It is stored `0600` as a NIP-49 `ncryptsec`, so your key is never on
disk in the clear:

```sh
# Generates a fresh key (or set SIGNER_SECRET_KEY to import an existing hex key),
# encrypts it, writes the file, and exits.
SIGNER_INIT=1 \
SIGNER_KEY_FILE="$HOME/.zig-nostr-signer.ncryptsec" \
SIGNER_PASSPHRASE="a strong passphrase" \
  zig build run
```

Then start serving:

```sh
SIGNER_KEY_FILE="$HOME/.zig-nostr-signer.ncryptsec" \
SIGNER_PASSPHRASE="a strong passphrase" \
SIGNER_RELAYS="wss://relay.example.com,wss://relay.two" \
SIGNER_CONNECT_SECRET=<optional connection secret> \
  zig build run
```

It decrypts the key once at startup, prints the signer's public key and the
`bunker://` token a client uses to connect, then dials each relay and serves
NIP-46 requests until stopped (reconnecting automatically if a relay drops).
Paste the token into a NIP-46-capable client to sign with a key that never
leaves this process.

For quick local testing you can skip the key file and pass an unencrypted key
directly with `SIGNER_SECRET_KEY=<64-char hex>`: but that keeps the key in your
environment in the clear, so prefer the encrypted file otherwise.

### Restricting what the signer will do

By default the signer honors every NIP-46 request behind the connection secret.
Two optional variables narrow that to least privilege:

- `SIGNER_ALLOWED_METHODS`: comma-separated methods the signer will honor, e.g.
  `get_public_key,sign_event`. `connect`, `ping`, and `logout` are always
  allowed so the handshake can't be locked out. Use this to run a **sign-only**
  bunker that refuses `nip44_decrypt`, so a connected client can't read your DMs
  through it.
- `SIGNER_ALLOWED_KINDS`: comma-separated event kinds `sign_event` may sign,
  e.g. `1,7`. A request to sign any other kind is denied.

Denied requests are answered with a NIP-46 error and logged.

### Interactive approval (GUI mode)

By default a request that passes the allowlist is answered immediately. Set
`SIGNER_APPROVAL_HTTP` to instead hold each one for interactive approval: the
daemon serves a small **loopback-only** HTTP API that a separate GUI connects
to, so you approve or deny each request on screen. The key never leaves the
daemon, the GUI only ever sees request metadata and sends back a yes/no.

In GUI mode the daemon can also boot **without a key** and let the GUI set one
up on first run, so a freshly downloaded app is turnkey. It reports its key
state on `GET /info` (`uninitialized` → `locked` → `unlocked`); the GUI creates
a key with `POST /setup` (generate a fresh one, or import an existing `nsec1…`
or 64-char hex) or decrypts an existing key file with `POST /unlock`. The key is
generated and decrypted inside the daemon, only the passphrase (and, on import,
the secret you type) ever crosses the API, never a derived key.

```sh
# Turnkey: no key file and no passphrase on the command line, the GUI provides
# them. SIGNER_KEY_FILE ($HOME/.zig-nostr-signer.key), SIGNER_APPROVAL_TOKEN_FILE
# ($HOME/.zig-nostr-signer.token) and SIGNER_RELAYS all default in this mode, so
# this alone is enough:
SIGNER_APPROVAL_HTTP="127.0.0.1:8787" \
  zig build run
```

You can still preconfigure the key instead of onboarding it, set
`SIGNER_KEY_FILE` + `SIGNER_PASSPHRASE` (or the dev-only `SIGNER_SECRET_KEY`) and
the daemon boots straight to `unlocked`.

The API is bound to loopback and every request must carry the bearer token
written (mode `0600`) to `SIGNER_APPROVAL_TOKEN_FILE`. Endpoints: `GET /info`,
`POST /setup`, `POST /unlock`, `GET /pending` (long-poll), `POST /decision`. A
request left unanswered past the timeout is denied, and the allowlist still
applies first, so disallowed requests are rejected without ever prompting.

## Roadmap

- [x] `bunker://` connection token from a key + relays
- [x] Relay listen/sign loop (NIP-46 `kind:24133` requests over a relay)
- [x] NIP-44 v2 encryption on every request and response (no NIP-04)
- [x] Encrypted key storage at rest (NIP-49 `ncryptsec`, scrypt + XChaCha20-Poly1305)
- [x] Per-request approval policy (method + event-kind allowlists)
- [x] Loopback approval API for interactive GUI approval
- [x] First-run key onboarding over the approval API (generate / import / unlock)
- [x] NIP-42 relay auth, so relays that require it still deliver requests
- [x] Native macOS approval app + downloadable build (one-line installer)
- [ ] Private messages: `nip44_encrypt`, a `sign_event` for the NIP-59 `kind:13`
      seal around each NIP-17 `kind:14` message, and `nip44_decrypt` to read one
- [ ] `nostrconnect://` client-initiated connections (NIP-46)

## License

MIT © Sepehr Safari
