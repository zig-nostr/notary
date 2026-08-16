**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.7.0

**You can hand Notary a key from the terminal.** Until now the only way in was the setup screen, which means your nsec goes through a window and usually the clipboard on its way. There is a command now:

```sh
/Applications/Notary.app/Contents/MacOS/signer import
```

It asks for your nsec and a passphrase without showing what you type, and stores the key encrypted exactly as it stores one it generated itself. It will not take a key as an argument, on purpose: a key on a command line ends up in your shell history and is visible to every other program running as you.

It writes the key for the next launch rather than handing it to a running Notary, so import first and then open it. That is not a shortcut. Notary's approval channel listens on a port that only the app itself knows, and a command able to reach it would need that port published somewhere anything could read.

**Opening Notary no longer leads with "delete my key".** The unlock screen showed a box asking you to type that phrase, every time, under the passphrase field. It is behind a red **Use another key** button now. Typing the phrase is still required once you get there, and cancelling clears what you typed.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon.**
