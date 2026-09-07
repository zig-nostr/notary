**Notary**: a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**, and Linux (x86_64 and aarch64).

### What's new in v0.10.10

**Fixed: on Debian the installer never checked for GTK 4.** The check that stops you downloading an app your machine cannot run was gated on finding `ldconfig` on your PATH, and Debian keeps `ldconfig` in `/usr/sbin`, which it does not put on a normal user's PATH. So on Debian the check silently did not happen: a machine without GTK 4 got a verified download, "Installed Notary", and then nothing at all when it started. It looks for `ldconfig` by absolute path now, and searches the library directories if there is none.

**A first start that fails now says so.** Notary was launched at the end of the install with its output thrown away, so a window that died on a missing library was indistinguishable from one that opened behind something. If it exits immediately the installer prints what it said. On the app that holds your key, that silence was the wrong trade.

**The download is verified, or not installed.** If the published SHA-256 could not be fetched, the installer used to warn and install anyway, which is a check any bad minute switches off.

**"Another Notary already has this key open" is now something you can read.** Two Notary windows cannot share one key: the daemon takes an exclusive lock on the key file and answers the second one with a refusal. The second window threw that refusal away, so you typed the right passphrase, the spinner stopped, and nothing happened, with nothing anywhere saying why. It happens in ordinary use: installing Plaza and then Notary, or re-running the installer while Notary is open.

**"This Mac" really does read "this computer" now.** v0.10.7 said that sweep was done everywhere. It had missed the sentence next to the backup button, which is the one place a Linux user is told why losing this machine loses their identity.

**A dead signer no longer tells you to check `SIGNER_BIN`.** That is a developer override nobody who used the one-line installer has ever set. It names the actual problem instead, which is that the two binaries have to sit together.

To be explicit about something v0.10.7 left ambiguous: that release fixed a **compile** error on older systems, and Ubuntu 22.04 and Debian 12 still cannot run these downloads. They carry GTK 4.6 and this needs 4.10. Building from source on them works if their GTK is new enough.

### What's new in v0.10.9

**Housekeeping, and one leak.** When a relay connection has gone quiet and what to do about it now comes from the `nostr` library rather than a copy kept here: the same three numbers and the same decision existed in Notary and in Plaza, written down in neither, so a correction to one would silently not reach the other.

The library release that carries it also fixes a leak on Notary's own reconnect path: freeing a relay connection freed everything except the connection object itself, so every reconnect left one behind for the life of the daemon.

Nothing you can see changed. Everything in v0.10.8 below is in this release too.

### What's new in v0.10.8

**There is a Linux download now.** 0.10.7 said Notary ran on Linux and offered only a macOS app, which was true and useless. This release carries a tarball for x86_64 and aarch64:

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/notary/main/scripts/install-linux.sh | bash
```

GTK 4 is the one runtime dependency, and the installer says so before it downloads anything rather than after the window fails to open. It verifies the SHA-256, installs into `~/.local` so nothing needs root and nothing lands outside your home directory, puts Notary in the launcher, and starts it. Pass `--archive <file>` to install a tarball you already have.

One download still brings up both halves: the window, and the `signer` daemon it spawns, which is where your key actually lives. They install side by side because the window finds the daemon beside its own executable, exactly as it does inside the `.app` on macOS.

### What's new in v0.10.7

**Notary runs on Linux.** The download on this page is still the macOS app. What changed is that the same window and the same keyholder now build and run on Linux, which is what lets Plaza's Linux build carry a keyholder of its own instead of asking you to bring one.

**Fixed: it would not build at all on distributions with older system libraries.** The daemon secret was minted through a function macOS guarantees and Linux does not, and on musl and on glibc below 2.36 that is a compile error rather than a warning. Ubuntu 22.04, Debian 11, RHEL 9 and every static build could not compile it. It asks the operating system for randomness through a portable route now.

**"This Mac" now reads "this computer"** everywhere it appears, including the sentence you read before allowing a signature under your name.

### What's new in v0.10.6

**Fixed: signing out and backing up your key had disappeared.** Both controls lived inside the card that shows the connection link, so a keyholder that publishes no link, which is every keyholder an app starts, showed neither. The only key control left was the one that deletes it. They are their own section now: whether you have a link to hand out and whether you can sign out are different questions.

**Fixed: the Sign out button did nothing when an app opened this window.** It refused whenever this window was not the one that started the keyholder, which is the case most people ever see. It signs out now, and the app that owns the keyholder starts a fresh one, locked.

**Fixed: "delete my key" could start a second keyholder.** When an app had handed its keyholder over, removing the key started another one of our own, on real relays, and replaced the secret this window uses so it could never reach the app's keyholder again. It hands back to the app instead.

**Fixed: a keyholder on no relays offered a connection link that went nowhere.** A `bunker://` link names the relays to reach a signer on. Built from an empty list it names nothing, and it was being shown as something to copy.

**Fixed: this window now closes itself** once the app that opened it got what it asked for, and tells that app whether a key was made here or brought.

**Clearer wording** in the section about signing for other apps, which used to promise a link in the state that has no link.
