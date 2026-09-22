---
name: altsign-skill
description: Sign iOS IPA files or .app bundles with altsign-cli using a free Apple ID, cached session, device UDID, provisioning profile creation, and 2FA-aware authentication. Use when a task needs to sign an iOS app for installation on a physical device, especially before ios-use install.
---

# AltSign CLI Skill

Use `altsign-cli` to sign iOS apps for physical-device installation. It accepts either an existing `.ipa` or a built `.app` bundle and always outputs a signed `.ipa`.

## Preconditions

- macOS with Xcode Command Line Tools.
- OpenSSL 3 installed, usually `brew install openssl`.
- A USB device UDID from `ios-use devices`, `xcrun devicectl list devices`, or Finder/Xcode.
- `altsign-cli` built in this repo:

```bash
./build.sh
```

Authenticate once as a standalone step:

```bash
./altsign-cli list --apple-id 'you@example.com'
```

The CLI reads the password and any trusted-device code from standard input.
When standard input is a terminal, password echo is disabled and restored.
Never put either secret in arguments, environment variables, scripts, or logs.
Later signing commands use the single cached session without credential
arguments; logging in with another Apple ID replaces that session.

## Choose a Team

Run `./altsign-cli list` to list every team using the cached account. Use
`./altsign-cli list --team-id TEAM_ID` to inspect a specific team's certificates
and App IDs. A single team is selected automatically; signing with multiple
teams requires `--team-id TEAM_ID`. Pass it on every signing command: selection
is not saved by `list`, and an unknown ID fails rather than choosing another team.

Use `./altsign-cli list --help` or `./altsign-cli sign --help` for command-specific
English help, examples, state locations and exit codes.

## Sign An IPA

```bash
./altsign-cli sign \
  --udid 00000000-0000000000000000 \
  --ipa path/to/App.ipa \
  --output path/to/App_signed.ipa
```

## Sign A Built .app

```bash
./altsign-cli sign \
  --udid 00000000-0000000000000000 \
  --app path/to/App.app \
  --output path/to/App_signed.ipa
```

The CLI packages the `.app` as a temporary IPA, resolves bundle IDs, creates or reuses App IDs and provisioning profiles, signs binaries, and writes the signed IPA.

## Install After Signing

Use `ios-use install` with the signed IPA:

```bash
ios-use install path/to/App_signed.ipa --udid 00000000-0000000000000000
```

Before reinstalling the same bundle, terminate the app and avoid leaving an old `activateApp --log` capture running. If install hangs with no progress output, inspect and clear stale app log capture processes before retrying.

## Failure Handling

- No valid cached session: run
  `./altsign-cli list --apple-id '<Apple ID>'` as a separate login step.
- Password or 2FA prompt: let the user enter it through standard input; do
  not ask them to paste it into chat, and do not guess or store it.
- Multiple teams or unknown team ID: run `list`, choose the intended ID, and
  pass `--team-id` to `sign` before allowing certificate/device changes.
- On failure, the CLI prints a `Diagnostics (exit code ...): ...log` path.
  Share that structured log for support; terminal/verbose output and session
  files may contain sensitive information.
- HTTP 429: respect any Retry-After information in the log; do not repeatedly
  retry or switch accounts. Other 4xx or Apple business errors require checking
  the failed stage and code; HTTP 200 alone does not mean authentication succeeded.
- HTTP 5xx or anisette errors: check network/VPN and retry only after identifying the cause.
- Free Apple ID profiles expire after 7 days; re-sign and reinstall to refresh.
- Some capabilities require paid Apple Developer Program membership.
