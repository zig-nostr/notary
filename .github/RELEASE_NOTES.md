**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.9.2

**The passphrase field no longer shows the passphrase.** Both setup screens and the backup panel drew every character as you typed it, which is the wrong default for something people type in a cafe, on a call, or into a screen recording. They draw stars now, with an eye beside the field for the times you want to read back what you typed.

It starts hidden every launch, and goes back to hidden after each send. Hiding it also keeps the characters out of the name the window publishes for that field, which is where anything on your Mac with accessibility access could have read them.

One rough edge, and it belongs to the toolkit rather than to Notary: replacing selected text with exactly as many characters leaves the typed ones on screen until your next keystroke. Reveal the field if you want to edit the middle of a passphrase.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon unless you ask for it.**
