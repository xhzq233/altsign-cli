# altsign-cli

One command to sign any IPA with your free Apple ID. No jailbreak, no paid developer account, no Xcode project.

```bash
./altsign-cli sign \
    --apple-id you@example.com \
    --password 'your-password' \
    --udid 00000000-0000000000000000 \
    --ipa MyApp.ipa
```

That's it. Authenticate, create certificates, register device, provision, and sign — all in one shot.

## Features

- **Free Apple ID** — no $99/year membership needed
- **Single command** — the entire signing pipeline runs end-to-end
- **2FA built-in** — prompts for the code inline, no extra steps
- **Auto certificate management** — creates, persists, and rotates signing certificates automatically
- **Multi-bundle** — handles `.appex` extensions in the IPA
- **Capabilities** — enable HealthKit, App Groups, Push, etc. via `--entitlement`
- **Session caching** — login once, reuse for ~1 year
- **No Xcode project** — only Command Line Tools needed

## Installation

**Requirements:** macOS 12+, Xcode Command Line Tools, OpenSSL 3.x

```bash
brew install openssl
git clone <repo-url> altsign-cli && cd altsign-cli
./build.sh
```

Produces a single `./altsign-cli` binary.

## Usage

### Sign an IPA

```bash
./altsign-cli sign \
    --apple-id you@example.com \
    --password 'your-password' \
    --udid 00000000-0000000000000000 \
    --ipa MyApp.ipa
```

Output: `MyApp_signed.ipa` (or specify `--output path.ipa`).

### Enable capabilities

```bash
./altsign-cli sign \
    --apple-id you@example.com \
    --password 'your-password' \
    --udid 00000000-0000000000000000 \
    --ipa MyApp.ipa \
    --entitlement healthkit,app-groups
```

### List certificates and App IDs

```bash
./altsign-cli list --apple-id you@example.com --password 'your-password'
```

### 2FA

When needed, the tool prompts:

```
2FA verification required. Enter code: _
```

Enter the 6-digit code from your trusted device. Done.

### Options

| Flag | Command | Description |
|------|---------|-------------|
| `--apple-id <email>` | all | Apple ID email |
| `--password <pwd>` | all | Apple ID password |
| `--udid <id>` | sign | Target device UDID |
| `--ipa <path>` | sign | Input IPA file |
| `--output <path>` | sign | Output path (default: `<input>_signed.ipa`) |
| `--entitlement <list>` | sign | Comma-separated capabilities (see below) |
| `--verbose` | any | Print full API responses |

### Available Capabilities

| Name | Capability | Free Account |
|------|-----------|--------------|
| `app-groups` | App Groups | Yes |
| `healthkit` | HealthKit | Yes |
| `push` | Push Notifications | Yes |
| `sign-in-with-apple` | Sign In with Apple | Yes |
| `associated-domains` | Associated Domains | **No** |
| `external-accessory` | Wireless Accessory | Yes |
| `gamecenter` | Game Center | Yes |
| `vpn` | Network Extension / VPN | **No** |

Capabilities marked **No** require a paid Apple Developer Program membership ($99/year).

## Limitations

- **macOS only** — relies on Apple private frameworks for authentication
- **7-day expiry** — free account profiles expire in 7 days; re-run to refresh
- **Some capabilities are paid-only** — VPN/Network Extension, Apple Pay, etc.

## Acknowledgments

Built on the protocol work of [AltSign](https://github.com/rileytestut/AltSign) by [Riley Testut](https://github.com/rileytestut).

## Disclaimer

For educational purposes and personal use. Not affiliated with Apple Inc.
