**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.6.0

**Notary remembers what you said.** It used to ask about every single request, forever. A client that signs in a loop asked in a loop, and a queue that never empties is a queue you stop reading, which is the opposite of what an approval screen is for.

An answer now lasts as long as you say: **Allow once**, **For a day**, **Always**, or **Deny**. Four buttons, one press each, rather than a yes/no prompt with the durations hidden somewhere else. A prompt that only offers yes and no is one people learn to hit yes on.

**What an answer covers.** One app, one thing it asked for, one kind of note. Saying "always" to an app posting notes does not let it encrypt your messages, and it does not carry over to a different app. Deny lasts an hour: long enough that a refused app cannot sit there pestering you, short enough that a wrong tap is not permanent.

**A question you never answered is not an answer.** If you were away from the machine and a request timed out, the app is refused for that request and nothing is written down. Walking away is not a decision, and storing it as a refusal would lock an app out over an absence.

Notary holds all this in memory, so it lasts as long as the signer is running and is gone when you quit.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Notary.app` to `/Applications`, and opens it, ready to use.

Notary is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/notary/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/notary#build). **Your key never leaves the daemon.**
