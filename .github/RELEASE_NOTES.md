**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.10.5

**Fixed: opening this window from an app left you unlocking the wrong keyholder.** An app that ships Notary starts its own keyholder and asks it to sign. This window went looking for a keyholder of its own instead: a well-known port when there was nothing there, and inside a packaged app a second keyholder started beside the first. So you typed your passphrase, this window said it was unlocked, and the app you opened it from was still sitting there with your key locked. Restarting did the same thing again.

An app can now hand this window the keyholder it is already using, and when it does, that one wins. One keyholder, shared, instead of two that cannot see each other.

The address arrives on the command line and the secret on the window's stdin, which is the same pair the keyholder itself takes and for the same reason: an address is not a secret, and a secret has no business on a command line where any program running as you can read it.
