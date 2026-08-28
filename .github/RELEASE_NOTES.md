**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.10.4

**Fixed: turning off "answering your other devices" looked like it did nothing.** The switch wrote the setting correctly, but the window reads its state back from the daemon, and the daemon kept answering with the value it read when it started. So the switch flipped back a moment later and the setting looked dead, when it had in fact been saved.

It still takes effect at the next start, because the relay connections are made once, with the key. What changed is that the window now tells you the truth about what it saved.

**And a setting that cannot be written is no longer reported as saved.** That write used to swallow its error and answer as though it had worked.
