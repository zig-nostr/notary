**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.10.3

**Fixed: the import command named the wrong app.** This window ships inside Plaza as well as on its own. Started from Plaza, it still told you to run `/Applications/Notary.app/Contents/MacOS/signer import`, which is not on your Mac at all unless you also installed Notary separately. It now names the signer it actually ships beside, so the command works for the app you opened it from.
