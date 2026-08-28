**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.10.2

**Fixed: an app that ships Notary could not get anything signed.** A daemon started by its own app asked for approval on the first signature of each kind, and then filed that question where nobody could answer it: the window that shows the queue finds a keyholder by a fixed port and a token file, and a daemon started this way uses neither. So every write from the app it serves was refused and left waiting for an answer that could not arrive.

Being handed a one-time secret on stdin by the process that started it is already proof of who is asking, and on this channel it is the only proof there can be. A daemon started that way now signs for its parent without a second question, and still writes down every use of the key exactly as before.

Nothing changes for a client that reaches Notary over a relay. Those prove who they are with their own keypair, and they still answer to the approval queue.
