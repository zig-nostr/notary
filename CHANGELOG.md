# Changelog

All notable changes to **Notary** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
While pre-1.0, minor versions add capability and patch versions are fixes.

## [Unreleased]

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
- Takes nostr v0.8.0 (from v0.6.0), which is where `ping`, `idleMs` and
  `shutdown` live, and which serializes writes on a connection: a connection
  being kept alive has two users on two threads, and over TLS half a record
  from each is a session that cannot be decrypted again.

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
