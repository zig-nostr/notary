**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.3.0

- **The install command works again.** It looks for `Notary.app`, and the previous release still carried `Signet.app` from before the app was renamed, so every install stopped with "the download did not contain Notary.app". Nothing was wrong with the script: there had been no release since the rename.
- **The app is called Notary.** It was Signet, which already meant a Bitcoin test network, and a signer sharing a name with a testnet is a signer people misread.
- **The setup screen reads in full.** "Create a new key, or import one you already have..." was cut off mid-sentence at the window's width.
- **A copy pass** over every screen and both READMEs, and the four screens are now in the README so you can see the app before installing it.

Full history in the [CHANGELOG](https://github.com/zig-nostr/notary/blob/main/CHANGELOG.md). **Your key never leaves the daemon.**

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon.**
