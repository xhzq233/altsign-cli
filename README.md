# altsign-cli

Sign any IPA or `.app` bundle with your free Apple ID. No jailbreak, paid
developer account, or Xcode project is required.

Authenticate once as a standalone step. The password and any two-factor code
are read from standard input. Password echo is disabled when standard input is
a terminal, and the password is never accepted as a command argument:

```bash
./altsign-cli list --apple-id you@example.com
```

Then sign with the single cached session:

```bash
./altsign-cli sign \
    --udid 00000000-0000000000000000 \
    --ipa MyApp.ipa
```

For an `.app` bundle:

```bash
./altsign-cli sign \
    --udid 00000000-0000000000000000 \
    --app path/to/MyApp.app \
    --output MyApp_signed.ipa
```

AltSign creates certificates, registers the device, provisions, packages when
needed, and signs in one flow.

## Features

- **Free Apple ID** — no $99/year membership needed
- **Single cached session** — log in with `list --apple-id`, then sign without credentials in argv
- **IPA and `.app` input** — pass an IPA with `--ipa` or an app bundle with `--app`
- **2FA built-in** — password and verification code use the same standard input
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
    --udid 00000000-0000000000000000 \
    --ipa MyApp.ipa
```

Output: `MyApp_signed.ipa` (or specify `--output path.ipa`).

### Sign an `.app`

```bash
./altsign-cli sign \
    --udid 00000000-0000000000000000 \
    --app path/to/MyApp.app \
    --output MyApp_signed.ipa
```

The tool packages the app into a temporary IPA, signs it, and writes a signed IPA to `--output`.

### Enable capabilities

```bash
./altsign-cli sign \
    --udid 00000000-0000000000000000 \
    --ipa MyApp.ipa \
    --entitlement healthkit,app-groups
```

### List certificates and App IDs

```bash
./altsign-cli list --apple-id you@example.com
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
| `--apple-id <email>` | list | Authenticate an Apple ID and replace the cached session |
| `--udid <id>` | sign | Target device UDID |
| `--ipa <path>` | sign | Input IPA file, or an `.app` bundle for compatibility |
| `--app <path>` | sign | Input `.app` bundle |
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

## Troubleshooting logs

After argument validation, each `list` or `sign` invocation creates a private
`altsign-XXXXXX.log` in `$TMPDIR` (falling back to
`NSTemporaryDirectory()`, usually under `/var/folders/.../T/`). The CLI prints its path at startup and
again with the process exit code at completion, including failures. If the
file cannot be created, a warning is printed and the command continues.

The file contains JSON lines with timestamps, OS/client markers, authentication
and query stages, HTTP status, numeric error codes, query counts, and parsed
`Retry-After` values. It does not copy terminal output, accounts, passwords,
verification codes, tokens, device/team identifiers, request/response bodies,
or arbitrary headers. This file can be shared for support; existing terminal
output (especially `--verbose`) and session files are separate and may contain
sensitive data. Logs have owner-only permissions, are kept after exit, and can
be deleted after diagnosis; macOS may eventually remove temporary files.

For HTTP 429, the CLI preserves error code 429 and logs any server-provided
retry delay/date. It does not automatically retry. A successful login followed
by an empty team query is a separate issue from authentication failure.

Developers can run `bash tests/test_cli_contract.sh ./altsign-cli` and
`bash tests/test_diagnostics.sh`. The latter uses local simulated responses
for HTTP 429, Apple plist errors, success and network failure; it never contacts
Apple and also checks log serialization and permissions.

## Limitations

- **macOS only** — relies on Apple private frameworks for authentication
- **7-day expiry** — free account profiles expire in 7 days; re-run to refresh
- **Some capabilities are paid-only** — VPN/Network Extension, Apple Pay, etc.

## Acknowledgments

Built on the protocol work of [AltSign](https://github.com/rileytestut/AltSign) by [Riley Testut](https://github.com/rileytestut).

## Disclaimer

For educational purposes and personal use. Not affiliated with Apple Inc.
