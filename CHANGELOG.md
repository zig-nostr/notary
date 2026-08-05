# Changelog

All notable changes to **Notary** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
While pre-1.0, minor versions add capability and patch versions are fixes.

## [Unreleased]

### Fixed
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
