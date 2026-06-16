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

First-time login needs `--apple-id` and `--password`. If Apple requires 2FA, the CLI prompts for the 6-digit code. When a valid session is cached, credentials can be omitted.

## Sign An IPA

```bash
./altsign-cli sign \
  --apple-id you@example.com \
  --password 'app-or-account-password' \
  --udid 00000000-0000000000000000 \
  --ipa path/to/App.ipa \
  --output path/to/App_signed.ipa
```

With a cached session:

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

- No cached session: rerun with `--apple-id` and `--password`.
- 2FA prompt: ask the user for the trusted-device code; do not guess or store it.
- HTTP 4xx from Apple: usually account, certificate, App ID, device registration, or capability eligibility.
- HTTP 5xx or anisette errors: check network/VPN and retry only after identifying the cause.
- Free Apple ID profiles expire after 7 days; re-sign and reinstall to refresh.
- Some capabilities require paid Apple Developer Program membership.
