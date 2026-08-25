**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.9.0

**You can take a copy of your key.** There was no way to get it out of this app before: not the nsec, not the encrypted file, and no instructions either. The screen that removes a key even told you to make sure you had its nsec written down first, with nothing anywhere that would give you one. A nostr key cannot be replaced, so a key that cannot leave the Mac holding it is an identity that dies with the Mac.

Press **Back up your key**, give it the passphrase, and pick one of two forms. The encrypted one is the file as it sits on disk, still useless to anyone without that passphrase, so it is safe to keep in a password manager or on paper. The other is the key itself, and says so in red, because anyone who reads it becomes you and there is no taking it back.

The passphrase is asked for either way, including the encrypted form that does not strictly need it: an unlocked signer is the normal state, and whoever is at the keyboard then is not necessarily the person who set it up.

**Sign out no longer hangs.** It started a second signer without stopping the first, and the first still owned the port, so the new one could never answer. The app sat at "Starting the signer…" until you quit and reopened it, with the old signer still running and still holding your key. Signing out now ends that process and keeps the key, so what comes back asks for your passphrase, which is what signing out was supposed to mean.

**Two screens scroll that did not.** Revealing a key, or opening "use another key" on the lock screen, adds enough to an already-full column that the bottom of it went under the status bar with no way to reach it.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon.**
