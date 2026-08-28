# Changelog

All notable changes to **Notary** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
While pre-1.0, minor versions add capability and patch versions are fixes.

## [Unreleased]

## [0.10.1] - 2026-08-28

### Changed

- **Whether this keyholder answers other devices is Notary's setting, not the
  starting app's.** It was a switch in the app that spawned the daemon, which
  made a client responsible for a keyholder's policy and had it storing a
  preference about a key it deliberately knows nothing about.

  The daemon reads its own config file, beside its own key, readable only by
  this user. An app that embeds Notary passes no flag and has no opinion.
  `--serve-relays` remains as an override for a terminal.

  Notary's window shows it and the daemon owns the answer: the toggle posts, the
  daemon writes, and the next `/info` is what the screen believes. A window
  keeping its own copy would eventually disagree with the thing actually
  signing, and the disagreement would be invisible.

  It says WHEN, too: relay threads are created once, with the key, so a running
  daemon cannot grow or drop them and the switch lands on the next start.

  Missing or unreadable config means off. The safe reading of "I could not tell"
  is not to put the process holding a key on the network.


## [0.10.0] - 2026-08-28

Notary can now sign for the app it is shipped inside, not only for clients that
reach it over a relay. The two are deliberately not the same daemon.

### Added

- **Signing for an app on this machine.** Notary serves `nostr.signer_ipc` on
  the same loopback channel its window already used, so an app that ships Notary
  can ask for a signature without a relay round trip.

  Which app may ask is settled by construction rather than by a credential. The
  daemon is started BY the app it signs for and is handed a one-time secret on
  stdin. That channel has no name, no path and no port, so nothing else on the
  machine can reach it, and holding it is the whole of the proof.

  This replaces a bearer token in a `0600` file. Measured on a Mac: a file like
  that separates USERS, not apps, so every app you run could read it; a
  process's argv and environment leak the same way; a pipe from a parent does
  not.

- **Two modes, never both.** `--serve-relays` makes the daemon a bunker on real
  relays, where a client proves who it is with its own keypair. Without it the
  daemon serves only the app that started it and connects to no relay. A
  keyholder that any local app can reach would have to answer "which app is
  this", and on the desktop nothing can.

- **One key, one keyholder.** Two processes cannot share a decrypted key, so a
  second daemon is refused rather than asking for the passphrase again. The
  refusal is decided before the passphrase is read, so a correct one is never
  reported as wrong.

- **Per-app answers on the local path**, by method and by event kind. Signing a
  note and signing a contact list are different risks. "Allow once" grants
  exactly one request and is spent on collection.

- **An audit log**, beside the key and readable only by you. Every use of the
  key, wrong passphrases, exports and adopted clients. By the id of what was
  signed, never its content; by peer and count for a cipher batch, never the
  messages.

### Fixed

- **`/setup` could mint a key over an import.** It inferred create-versus-import
  from an empty secret, so a client that meant to import and sent nothing was
  given a brand new identity. It takes an explicit method now.

- **Kinds 14 and 15 are refused on every path.** They are the unsigned rumors
  inside a NIP-59 gift wrap, and a signature on one destroys the deniability the
  scheme exists for. The relay path used to show that request to a person
  instead, which is worse than refusing it.

- Unanswered local questions expire, so they cannot fill the approval queue and
  stop every other question, relay requests included.

- A failed audit-log rollover no longer writes over the oldest entries.


## [0.9.2] - 2026-08-27

### Fixed
- **The passphrase field no longer shows the passphrase.** Both onboarding
  screens and the backup panel drew every character in the clear, which is the
  wrong default for something people type in a cafe, on a call, or into a screen
  recording. They draw stars now, with an eye beside the field for the times you
  want to read back what you typed. It starts hidden on every launch, and goes
  back to hidden after each send.

  The mask is one star per byte rather than a prettier bullet, and that is load
  bearing rather than lazy: the runtime hands back caret offsets into the string
  it drew, so a mask exactly as long as the text maps them straight through and
  the caret lands on the character you clicked. Inserting is the one gesture
  where the two disagree, and the buffer now follows the drawn caret home rather
  than quietly typing somewhere you are not looking.

  Hiding it also keeps the characters out of the accessible name the window
  publishes for that field, which is where anything with accessibility access
  would have read them.

  One rough edge is left, and it belongs to the toolkit rather than to this
  change: replacing selected text with exactly as many characters leaves the
  typed ones on screen until the next keystroke, because the toolkit repaints
  its own copy of the line whenever the length it was handed has not moved.
  Reveal the field if you want to edit the middle of a passphrase.

## [0.9.1] - 2026-08-27

### Fixed
- **A key imported from a terminal no longer needs a restart.** `signer import`
  takes an nsec from a terminal and writes it encrypted, and a Notary that was
  already open never found out: the window sat on "Set up your signer" until the
  app was quit and reopened, which is a strange thing to ask of somebody who has
  just typed their nsec and chosen a passphrase for it.

  Both halves were blind. The daemon decided its state once, at boot, from
  whether the key file existed; `Gate.rescan` asks the disk again, and `/info`
  calls it before answering, because that is the poll the window sits on while it
  waits. Only ever uninitialized to locked, by compare-exchange: `/info` is polled
  while serving too, and a rescan that could reach an unlocked gate would lock a
  running signer out of its own key on a routine status poll. The window, for its
  part, only re-polled `/info` while already serving, so the two screens that most
  needed it never asked again.

  The import still refuses to speak to a running daemon, and that stays
  deliberate: the control port is ephemeral and told only to the window that
  spawned it, so a CLI able to reach it would need that port published somewhere
  readable, which is the property being protected. The key goes to disk and the
  daemon finds it there. So this lands on the unlock screen rather than straight
  into serving, which is one passphrase instead of a relaunch, and the passphrase
  was chosen seconds earlier in the same terminal.

## [0.9.0] - 2026-08-26

### Added
- **Back up your key.** There was no way to get the key out of this app: not the
  nsec, not the encrypted file, and no instructions either. The screen that
  removes a key even told you to make sure you had its nsec written down first,
  with nothing anywhere that would give you one. A nostr key cannot be replaced,
  so a key that cannot leave the Mac holding it is an identity that dies with the
  Mac.

  Two forms, and the difference is the point. The encrypted one is the NIP-49
  `ncryptsec1…` exactly as it sits on disk, still useless without the passphrase,
  which is the one to keep. The other is the key in the clear and says so in red.

  The passphrase is required for both, including the encrypted form that does not
  strictly need it: an unlocked signer is the normal state, and whoever is at the
  keyboard then is not necessarily the person who set it up. Nothing is kept
  afterwards.
- `POST /lock` and `POST /export` on the daemon's loopback API.

### Fixed
- **Sign out stopped hanging.** It spawned a second daemon without ending the
  first, which still owned the loopback port, so the new process could not bind
  and never printed the port line the window waits for. The app parked at
  "Starting the signer…" until it was restarted, with the old daemon still
  serving and still holding the key. `/lock` ends the process and keeps the key,
  so the one that follows comes up locked and asks for the passphrase.
- **The serving screen and the lock screen scroll.** Revealing a key, or opening
  "use another key", adds enough to a full column that the bottom of it went
  under the status bar with no way to reach it.

## [0.8.1] - 2026-08-22

### Fixed
- **The window could not reach its own signer.** Native SDK 0.9.1 began
  confining raw file effects to an app's own directories unless the app declares
  the new `filesystem` permission. The window reads the daemon's bearer token
  from `$HOME`, which is outside every one of them, so the read was rejected and
  nothing said so: the token never arrived, the phase never advanced, and the
  app sat on "Connecting to the signer…" forever, looking exactly like a network
  fault. It is declared now.

  The released 0.8.0 was never affected. It was built against an older CLI, and
  the pin moved the day after that release, so the break lived only on `main`.
  Nothing caught it because `check`, `test` and `build` all pass on an app that
  cannot reach its daemon, and none of them launches it. There is now a test that
  fails if the permission is ever dropped again.

- **The setup screen overclaimed.** It said the app "only sends the passphrase".
  That is true when you create a key and false when you import one, which is the
  one moment the secret does pass through the window. It now says which is which.

### Changed
- The screenshots are retaken from the current app. The approval card shows the
  four answers it actually offers (allow once, for a day, always, deny) along
  with who is asking and what would be signed, where the old picture showed two
  buttons and neither.

## [0.8.0] - 2026-08-16

### Added
- **The terminal import is offered in the window.** `signer import` shipped last
  release and nothing in the app mentioned it, so the only way in that anybody
  could see was the one that puts an nsec through a text field and usually the
  clipboard. The setup screen now shows the command beside the paste field, with
  a button to copy it, the same way Plaza's key window has always offered it.

### Changed
- **One status line instead of four.** The window opened with its own name above
  the phase above the key, and then counted the queue again at the bottom. That
  is four lines of chrome in a small window, three of which said nothing after
  the first second, and the app's name was already in the title bar. The body
  starts at the top now and there is a single status line at the bottom: the
  phase while onboarding, the key and the queue count once serving.

  The setup screen also scrolls, so a taller state cannot paint underneath the
  status bar the way the import branch did.

## [0.7.0] - 2026-08-16

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
