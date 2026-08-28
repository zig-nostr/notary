**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.10.1

**Notary can sign for the app it is shipped inside**, not only for clients that reach it over a relay. The two are deliberately not the same daemon.

Which app may ask is settled by construction rather than by a credential. The daemon is started *by* the app it signs for and handed a one-time secret on its stdin. That channel has no name, no path and no port, so nothing else on your Mac can reach it, and holding it is the whole of the proof.

This replaces a token in a `0600` file. Measured on a Mac: a file like that separates *users*, not apps, so every app you run could read it. A process's arguments and its environment leak the same way. A pipe from a parent does not.

**Two modes, never both.** Run Notary on its own and it is a bunker on real relays, where a client proves who it is with its own keypair. Started by an app that ships it, it serves only that app and connects to no relay. A keyholder that any local app can reach would have to answer "which app is this", and on the desktop nothing can.

Whether it *also* answers your other devices is Notary's own setting, in Notary's window, stored beside the key. The app that starts it has no say and stores nothing.

**One key, one keyholder.** Two processes cannot share a decrypted key, so a second Notary is refused instead of asking for your passphrase again. The refusal is decided before the passphrase is read, so a correct one is never reported as wrong.

**An audit log**, beside the key and readable only by you: every use of the key, wrong passphrases, exports, and clients you let in. By the id of what was signed, never its content; by peer and count for a batch of messages, never the messages.

**Fixed:** setup could mint a new key over an import that arrived empty, giving you a brand new identity instead of the one you meant to bring. Gift-wrap rumors (kinds 14 and 15) were refused on one path and shown to you as a prompt on the other. Unanswered local requests could fill the approval queue and stop every other request, including those from relays.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon unless you ask for it.**
