**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.8.0

**The terminal way in is now visible.** v0.7.0 added a command that takes your nsec from a terminal without it passing through the window or the clipboard, and then nothing in the app told you it existed. The setup screen shows it now, beside the paste field, with a button to copy it. Both ways work; one of them keeps your key out of more places.

**One status line instead of four.** Notary used to open with its own name above the current phase above your key, and then count the queue again at the bottom. That is a lot of the window spent telling you things you knew, in an app whose whole job is to show you one question at a time. The screen starts with the actual content now, and there is a single line at the bottom.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon.**
