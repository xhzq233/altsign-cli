# altsign-cli

Sign any IPA or `.app` bundle with your free Apple ID. No jailbreak, paid
developer account, or Xcode project is required.

Authenticate once as a standalone step. The password and any two-factor code
are read from standard input. Password echo is disabled when standard input is
a terminal, and the password is never accepted as a command argument:

```bash
./altsign-cli list --apple-id you@example.com
```

Then sign with the single cached session. By default, the first team returned
by Apple is used; pass `--team-id` to select another team:

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

### Help

```bash
./altsign-cli --help
./altsign-cli list --help
./altsign-cli sign --help
./altsign-cli help sign
```

`-h` is also supported. Help uses English and requires no account, network,
session, or diagnostic log. Application messages are in English; account/team
names and messages supplied by Apple are displayed as returned.

### List and select teams

```bash
./altsign-cli list --apple-id you@example.com
./altsign-cli list                           # reuse the cached account
./altsign-cli list --team-id ABCDE12345       # inspect one team's resources
```

Without `--team-id`, `list` displays every team's name, ID and type, then
queries certificates and App IDs for the first team returned by Apple.
`sign` also defaults to the first returned team, preserving the original
selection behavior. Team type alone does not establish paid membership.

Use an explicit ID to select another team for either command:

```bash
./altsign-cli sign --team-id ABCDE12345 --udid DEVICE_ID --ipa MyApp.ipa
```

An unknown explicit ID prints the available teams and fails before
certificate/device changes; it never falls back to another team. Selection is
per command, not saved by `list`, and does not prefer paid membership. Apple's
team order can change between calls; use an explicit ID for a consistent choice.
The selected team's name, ID and type are shown before signing operations.
Existing signing behavior can revoke a certificate if its private key is not
available locally; use the intended team's keys when signing.


### 2FA

When needed, the tool prompts:

```
2FA verification required. Enter code: _
```

Enter the 6-digit code from your trusted device. Done.

### Options

| Flag | Command | Description |
|------|---------|-------------|
| `--apple-id <email>` | list | Reuse this account’s valid session or authenticate; a successful new login replaces the cached account |
| `--team-id <id>` | list, sign | Select a team; omission uses the first team returned by Apple |
| `--udid <id>` | sign | Target device UDID |
| `--ipa <path>` | sign | Input IPA file, or an `.app` bundle for compatibility |
| `--app <path>` | sign | Input `.app` bundle |
| `--output <path>` | sign | Output path (default: `<input>_signed.ipa`) |
| `--entitlement <list>` | sign | Comma-separated capabilities (see below) |
| `--verbose` | list, sign | Print full API responses to the terminal (sensitive) |
| `-h`, `--help` | global, list, sign | Display help without authentication |

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

Developers can run `bash tests/test_cli_contract.sh ./altsign-cli`,
`bash tests/test_teams.sh` and `bash tests/test_diagnostics.sh`. The team test
checks selection, refusal before certificate operations, and help without state
side effects. The diagnostics test uses local simulated responses
for HTTP 429, Apple plist errors, success and network failure; it never contacts
Apple and also checks log serialization and permissions.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Command succeeded, or help displayed |
| 1 | Operation failed (including team selection), or required signing input is missing |
| 2 | Cached session missing/expired, or password input failed |
| 64 | Unknown command, unsupported/duplicate option, or missing/empty option value |

Apple business errors and HTTP errors are reported separately; for example,
HTTP 429 produces a command exit code of 1 while preserving error code 429 in
the error and diagnostic log. A successful HTTP response may still contain an
Apple business error. Logs survive command exit and may be deleted after use.

## Limitations

- **macOS only** — relies on Apple private frameworks for authentication
- **7-day expiry** — free account profiles expire in 7 days; re-run to refresh
- **Some capabilities are paid-only** — VPN/Network Extension, Apple Pay, etc.

## Acknowledgments

Built on the protocol work of [AltSign](https://github.com/rileytestut/AltSign) by [Riley Testut](https://github.com/rileytestut).

## Disclaimer

For educational purposes and personal use. Not affiliated with Apple Inc.
