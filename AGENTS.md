# AGENTS.md

A guide to this repository for coding agents and the people working with them.

## What Notary is

A native NIP-46 remote signer ("bunker") for macOS and Linux, written in Zig on the [`nostr`](https://github.com/zig-nostr/nostr) library. The secret key lives in a headless daemon; a separate native window shows each request and sends back the answer (allow once, for a day, always, or deny). The key is encrypted at rest with NIP-49.

Keeping the key out of reach is the point of the whole project. The key is generated, decrypted and used only inside the daemon. Never add a path that logs it, returns it over the approval API, or passes it through the window beyond the existing import screen.

## Layout

Two Zig packages, each with its own `build.zig`, `build.zig.zon` and `.zigversion`:

```
daemon/          # the signer ("signer" binary): NIP-46 over relays, the approval API, the key file
  src/main.zig
  src/approval.zig, approval_http.zig   # pending requests and the loopback HTTP the window talks to
  src/relay_keeper.zig                  # relay connections
  src/audit.zig, onboarding.zig
gui/             # the approval window ("notary" binary), a Native SDK app
  src/app.native # declarative markup
  src/main.zig   # model, update, daemon supervision
  src/tests.zig
  app.zon        # app manifest; its .version is the release version
scripts/         # installers and the installer check
.github/RELEASE_NOTES.md  # the text of each release page
CHANGELOG.md
```

The daemon runs in one of two modes, never both: standalone, a bunker on real relays; or embedded, the private keyholder of one parent app (Plaza), reachable only down a pipe that parent was handed at startup, with no relay connections. A signer that any local app can reach cannot tell which app is asking, so do not add one.

## Build and test

Zig 0.16.0 exactly.

```sh
cd daemon
zig build
zig build test
zig fmt --check .
```

The window needs the Native SDK CLI (`npm install -g @native-sdk/cli@0.10.1`, the version CI uses):

```sh
cd gui
native check   # markup and manifest
native test
native build
zig fmt --check src
```

To run the window against a daemon you built, set `SIGNER_BIN` to it (`daemon/zig-out/bin/signer`) when starting `native dev`. The window then starts and supervises that daemon the way a packaged app does with the one beside it. The full example, with the key and relay variables, is under "Managed mode" in `gui/README.md`; `daemon/README.md` covers key setup and the approval API.

## Conventions

- `zig fmt` is the formatter; CI fails on unformatted code, in both packages.
- [Conventional Commits](https://www.conventionalcommits.org/). One concern per pull request, with its tests, and every pull request links its issue.
- Never commit to `main`; everything lands through a reviewed pull request.
- A release is a version bump in `gui/app.zon` plus a matching `### What's new in vX.Y.Z` section in `.github/RELEASE_NOTES.md`. CI checks that the two agree. Merging the bump tags the release and builds the macOS app and the Linux tarballs.
- Validate everything a client or relay sends at the boundary. Every request that reaches the daemon is untrusted until it is authenticated.

## Related

- [`nostr`](https://github.com/zig-nostr/nostr): the protocol library. It has an agent skill: `npx skills add zig-nostr/nostr`.
- [Plaza](https://github.com/zig-nostr/plaza): the client that bundles Notary as its keyholder, pinned to a Notary release.
- [deed](https://github.com/zig-nostr/deed): a nostr command line, useful for checking what a signed event looks like on a relay.
- [zignostr.com](https://zignostr.com/notary): the project site, also served as Markdown at `/notary.md`.
