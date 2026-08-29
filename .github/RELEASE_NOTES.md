**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### What's new in v0.10.6

**Fixed: signing out and backing up your key had disappeared.** Both controls lived inside the card that shows the connection link, so a keyholder that publishes no link, which is every keyholder an app starts, showed neither. The only key control left was the one that deletes it. They are their own section now: whether you have a link to hand out and whether you can sign out are different questions.

**Fixed: the Sign out button did nothing when an app opened this window.** It refused whenever this window was not the one that started the keyholder, which is the case most people ever see. It signs out now, and the app that owns the keyholder starts a fresh one, locked.

**Fixed: "delete my key" could start a second keyholder.** When an app had handed its keyholder over, removing the key started another one of our own, on real relays, and replaced the secret this window uses so it could never reach the app's keyholder again. It hands back to the app instead.

**Fixed: a keyholder on no relays offered a connection link that went nowhere.** A `bunker://` link names the relays to reach a signer on. Built from an empty list it names nothing, and it was being shown as something to copy.

**Fixed: this window now closes itself** once the app that opened it got what it asked for, and tells that app whether a key was made here or brought.

**Clearer wording** in the section about signing for other apps, which used to promise a link in the state that has no link.
