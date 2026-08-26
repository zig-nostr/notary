**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.9.1

**A key imported from a terminal no longer needs a restart.** `signer import` takes your nsec from a terminal and stores it encrypted, and a Notary that was already open never found out. The window sat on "Set up your signer" until you quit and reopened the app, which is a strange thing to ask of somebody who has just typed their nsec and chosen a passphrase for it.

It notices now, in about a second, and asks for that passphrase. Importing still writes the key to disk rather than handing it to the running app, and that is on purpose: the channel Notary listens on is deliberately hard to find, so nothing else on your Mac can reach it, and a command that could would have to publish where it is. So this lands on the unlock screen rather than straight into serving. One passphrase, instead of a relaunch.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon unless you ask for it.**
