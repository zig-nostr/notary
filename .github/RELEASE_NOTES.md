**Notary** — a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.2.0

- **Bunker URL in the app** — the serving screen now shows the `bunker://` connection URL with a Copy button, so you can connect a client without touching the logs.
- **Live relay status** — watch each relay connect in real time on the serving screen.
- **One-line install** — the `curl … | bash` command below is new: it verifies the download's checksum and clears quarantine, so the app opens cleanly with no Gatekeeper detour.

Full history in the [CHANGELOG](https://github.com/zig-nostr/notary/blob/main/CHANGELOG.md). **Your key never leaves the daemon.**

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it — ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon.**
