**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.4.0

- **A relay that goes quiet is noticed.** Each relay thread waits inside `receive` until its relay says something, so a peer that went away without closing left that thread waiting forever. For a signer that is the worst kind of failure: remote signing simply stops, the approval window never opens, the client's request times out, and the daemon still reports the relay as connected.

  A keeper thread now watches every connection, pings after thirty seconds of silence and half-closes the socket after ninety, which returns the blocked read and lets the relay thread reconnect. It has to be a separate thread, because a thread waiting on a dead peer is the last thing able to notice that it is waiting.

- **Relays have a fourth state, `quiet`.** The socket is open, nothing has come down it for a while, and a keepalive is out unanswered. Not disconnected, because nothing has failed; not plainly connected either, because the last evidence of that is a minute old. The GUI shows it in amber, and `/info` reports it.

- **A request cannot get past the staleness check by choosing an absurd timestamp.** Notary refuses a NIP-46 request older than two minutes, which is what stops a request captured off the relay from being replayed later. That age was a plain subtraction on a `created_at` the sender picked, and a request stamped with the smallest number an `i64` holds made the difference too wide to fit, so it wrapped to a *negative* age. A negative age is not greater than two minutes, so the check waved it through.

  The arithmetic saturates now: a timestamp that far away reads as stale, which is what the check meant all along. This is a guard rather than the lock, since a request still has to be sealed to your bunker and authorized before anything is signed, but a replay window you can open by choosing a number is not one worth leaving open in the thing that holds your key.

Full history in the [CHANGELOG](https://github.com/zig-nostr/notary/blob/main/CHANGELOG.md). **Your key never leaves the daemon.**

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon.**
