**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.5.0

**Clients can invite Notary now, not just the other way round.** Until now the only way to connect was to copy Notary's `bunker://` URL and paste it into your client. Most clients offer the opposite: they show a `nostrconnect://` link and wait. Paste one into Notary and it adopts that client.

**Three relays instead of one.** Notary served on a single relay, which means it stops signing the moment that relay does, and from your client's side that failure is silent: the request goes out, nothing ever answers, and the app just sits there. It now serves three, run by three different operators, so one going down is one connection reconnecting rather than a signer that has quietly stopped.

Serving several relays needed more than a longer list. Your client publishes each request to every relay in the token, so one thing you asked for arrives several times. Notary used to treat those as separate: two approval windows for one question, and two signatures published for one intent. It also meant a client that connected over one relay and then asked over another was told it had never connected. Both are fixed.

**Signing out.** There was no way out of an account: once a key was unlocked, Notary served it until the process died. Signing out locks the signer and asks for your passphrase again.

Using a different key is a separate button, because it is a different thing: it removes the key from this Mac, and that is the only copy here. It asks you to type a phrase to confirm, and the button does nothing until you do. Have your nsec written down before you use it.

**Under it:** the release you are reading was built by CI and its tests ran before it was published. That was not true of previous releases, which went from build straight to publish with nothing checking them.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon.**
