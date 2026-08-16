# Changelog

All notable changes to **Notary** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
While pre-1.0, minor versions add capability and patch versions are fixes.

## [Unreleased]

### Added
- **`signer import`.** A key could only come in through the app's own setup
  screen, which means it goes through the window before it reaches the signer.
  Pasting it into a terminal instead keeps it out of the app: echo is off, and
  it is never an argument, so it is not in shell history and not visible in `ps`
  to anything else running as you. Notary stores it encrypted at rest like a key
  it generated itself.

  It writes the file for the next launch rather than handing the key to a
  running Notary. The daemon binds an ephemeral port and tells only the app that
  spawned it which one; a command that could reach it would need that port
  published somewhere readable, which is exactly what keeps another process on
  the machine away from the control channel.

### Changed
- **The way out of a key is folded away.** Opening Notary to unlock it led with
  a box telling you to type "delete my key", which is a strange first thing to
  show somebody who only wants their passphrase field. It is behind a red "Use
  another key" button now. The typed confirmation is unchanged and still exact:
  folding it away is one guard, not a replacement for the other.

## [0.6.0] - 2026-08-16

### Added
- **Answers that last.** Every request was asked fresh, so a client that signs
  in a loop asked in a loop, and a queue that never empties is a queue nobody
  reads. An answer can now stand for the rest of the session,
  or for a day, or just for this one request: "Allow once", "For a day", "Always" and "Deny" are each one press,
  rather than a yes/no prompt with the durations behind a second screen.

  An answer covers one client, one method and one event kind. A different kind
  from the same client is a separate question. A denial stands for an hour, long
  enough that a refused client cannot pester and short enough that a misclick is
  not permanent. A request nobody answers is not written down at all: walking
  away from the machine is not a decision, and storing silence as a refusal
  would lock a client out over an absence.

  The record lives in memory, so it lasts as long as the signer is serving and
  is gone when it stops.

## [0.5.0] - 2026-08-15

### Added
- **`nostrconnect://`.** Notary could only be connected one way round: copy its
  `bunker://` URL and paste it into a client. The other direction is what most
  clients actually offer, a link they show and wait on. Paste one in and Notary
  adopts that client.

  The reply carries the link's own secret as its result, in place of `"ack"`,
  which is how the client knows the signer that answered is the one it invited.
  Answering `"ack"` is ignored by every client and the connection never
  completes, with nothing to see on either side.

  The answer goes to the relays the client named, which are not necessarily
  ours, so this is the one place the daemon dials an address it did not choose:
  `wss://` only, no control characters, and at most four relays tried.

- **Signing out, and using another key.** Two things, deliberately separate.
  Signing out locks the signer and is a restart, which is the honest
  implementation: the relay threads were handed the key by value when serving
  began, so nothing short of ending the process takes it back. Using another key
  removes the key file, sits behind a typed phrase matched exactly, and ends the
  process, because the relay threads still hold the key that was just deleted.

  Sessions do not outlive the key they were granted against, and anything
  waiting for a decision is rejected rather than dropped: a relay thread is
  parked on each of those and freeing the slot would strand it.

### Changed
- **Three relays by default, not one.** The GUI served on `wss://relay.damus.io`
  and nothing else. A signer on a single relay stops signing when that relay
  does, and from the client's side the failure is silent: the request is
  published, nothing answers, and the app sits there. The three are Amber's
  verbatim, three separate operators. Deliberately not `relay.nsec.app`, which
  is the obvious pick and belongs to a project that looks unmaintained.

- Serving several relays was already possible and was not correct. One intent
  arrives as the same event id on every relay thread, and two things were held
  per thread that had to be shared: the record of answered requests, so each
  relay answered its own copy (two approval prompts, two signatures for one
  intent), and the set of connected clients, so a client that connected over one
  relay and asked over another was told "not connected". Both are now created
  once and shared. Takes nostr v0.11.0, which is what changed those signatures.

### Fixed
- The release workflow went from build straight to package to publish, running
  **no tests at all**, on the one artifact nobody gets to re-check. Both suites
  gate it now, the publish step is idempotent so a re-run is not a red X on work
  that succeeded, and the tag has to agree with `gui/app.zon` so a release
  cannot tell people they are running the previous version.

## [0.4.0] - 2026-08-12

### Fixed
- **A relay that goes quiet is noticed.** Each relay thread blocks in `receive`
  until its relay says something, so a peer that went away without closing left
  that thread waiting forever. For a signer the symptom is the worst kind:
  remote signing simply stops, the approval window never opens, the client's
  request times out, and the daemon still reports the relay as connected.

  A keeper thread now watches every connection: it pings after 30s of silence
  and half-closes the socket after 90s, which returns the blocked read and lets
  the relay thread reconnect through its own path. It has to be a separate
  thread, because a thread waiting on a dead peer is the last thing able to
  notice that it is waiting.

  Amethyst's numbers, from their survey of 122 relays: idle timeouts cluster
  around 60, 120, 240, 300 and 600 seconds, and a ping only holds a connection
  open reliably when its interval is at most about half the shortest. Ninety
  seconds is three missed answers. Answering the relay's pings does not
  substitute for sending our own, because a relay's idle timer counts what it
  receives.

### Added
- `/info` reports a fourth relay state, `quiet`: the socket is open, nothing has
  come down it for a while, and a keepalive is out unanswered. Not disconnected,
  because nothing has failed; not plainly connected either, because the last
  evidence of that is a minute old. The GUI shows it in amber.

### Changed
- Takes nostr v0.9.0 (from v0.6.0). v0.8.0 is where `ping`, `idleMs` and
  `shutdown` live, and where writes on a connection became serialized: a
  connection being kept alive has two users on two threads, and over TLS half a
  record from each is a session that cannot be decrypted again.

  v0.9.0 carries a fix on this daemon's own request path. `worthAnswering`
  measured a request's age with a plain subtraction on a `created_at` the
  sender chose. A request stamped `minInt(i64)` makes the difference wider than
  an i64 holds, so it wrapped to a NEGATIVE age, and a negative age is not
  greater than the limit: the staleness guard accepted the one timestamp most
  obviously worth refusing. The arithmetic saturates now, so a timestamp that
  far away reads as stale, which is what both branches were reaching for.

  It is a guard rather than the lock: a request still has to be sealed to this
  bunker and authorized before anything is signed. But a replay window that can
  be opened by choosing a number is not a window anybody should have to argue
  about, and this daemon is the one thing here holding a key.

## [0.3.0]

### Changed
- The app is called **Notary**. It was Signet, which already meant a Bitcoin test
  network, and a signer that shares a name with a testnet is a signer people
  misread. Every surface says Notary now.
- A copy pass over everything a reader sees: the setup screen, the serving
  screen, the approval prompts and both READMEs.

### Fixed
- **The installer works again.** It looks for `Notary.app`, and the newest release
  still carried `Signet.app` from before the rename, so every install failed with
  "the download did not contain Notary.app". Nothing was wrong with the script:
  there had been no release since the app was renamed.
- The first-run setup screen no longer truncates its explanation. "Create a new
  key, or import one you already have…" was cut off mid-sentence at the window's
  width; it now wraps and reads in full.

## [0.2.0] - 2026-07-13

### Added
- The `bunker://` connection URL now appears on the serving screen with a **Copy**
  button, after both creating a new key and unlocking or importing an existing one so you can hand a client the connection string without reading the daemon's
  logs. The URL (and its connection secret) is assembled inside the daemon and
  never leaves it (#23).
- **Connected relay status**: the serving screen lists each configured relay with a
  live indicator (connecting…, connected, or offline) refreshed periodically
  (#24).
- A **one-line macOS installer**:
  `curl -fsSL …/scripts/install-macos.sh | bash` resolves the latest release,
  verifies its SHA-256, installs `Notary.app` to `/Applications`, clears the
  download quarantine, and opens it (#25).

### Changed
- Install docs reduced to the single installer command, leading with the
  quarantine-clear step instead of a multi-path download/unzip walkthrough
  (#22, #25).
- Bumped the Native SDK CLI to 0.4.4: crisper rendering (device-pixel-snapped
  borders, linear-light edge blending), no source changes (#26).

## [0.1.1] - 2026-07-12

### Fixed
- A Finder/LaunchServices launch no longer quits with "signer exited code 1". A
  double-click hands the app a minimal environment (no `SIGNER_*` variables), so
  the GUI now passes the approval address to the daemon over `argv` and the daemon
  still reaches GUI mode (#21).

## [0.1.0] - 2026-07-12

### Added
- Initial ad-hoc-signed macOS release: a single `.app` bundling the signer daemon
  and the native approval GUI, first-run key onboarding (create or import,
  encrypted at rest via NIP-49), and the approval queue over the daemon's
  loopback-only API. Superseded by 0.1.1.
