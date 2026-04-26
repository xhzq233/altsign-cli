# altsign-cli

A command-line IPA re-signer for non-jailbroken iOS devices. Works with a **free Apple Developer account** — no paid membership required.

Heavily inspired by and based on the protocol-level reimplementation of [AltSign](https://github.com/rileytestut/AltSign) by Riley Testut. AltSign's SRP authentication flow, Apple Developer Services API client, and overall signing architecture served as the primary reference for this project.

## Features

- **Free Apple Developer account** — no $99/year membership needed
- **End-to-end signing pipeline** — login, certificate management, device registration, provisioning, and re-signing in a single command
- **SRP authentication** — full Apple GSA (Grand Slam) protocol with 2FA support
- **Automatic certificate lifecycle** — creates development certificates on demand, persists private keys locally, revokes and recreates when keys are missing
- **Bundle ID override** — rewrite the app's bundle identifier at sign time via `--bundle-id`
- **Session persistence** — authentication sessions are cached and reused (valid ~1 year), avoiding repeated logins
- **No Xcode required** — only the Command Line Tools

## Quick Installation

**Prerequisites:** macOS 12+ with Xcode Command Line Tools and OpenSSL 3.x.

```bash
brew install openssl
git clone <repo-url> altsign-cli && cd altsign-cli
./build.sh
```

This produces a single `./altsign-cli` binary with no runtime dependencies beyond macOS system frameworks.

## Usage

### Sign an IPA

```bash
./altsign-cli sign \
    --apple-id you@example.com \
    --password 'your-password' \
    --udid 00000000-0000000000000000 \
    --ipa MyApp.ipa
```

This runs the full pipeline: authenticate → fetch team → resolve certificate → register device → resolve App ID → download provisioning profile → re-sign IPA. The signed output defaults to `MyApp_signed.ipa`.

**With a custom bundle ID:**

```bash
./altsign-cli sign \
    --apple-id you@example.com \
    --password 'your-password' \
    --udid 00000000-0000000000000000 \
    --ipa MyApp.ipa \
    --bundle-id com.example.myapp \
    --output MySignedApp.ipa
```

### List certificates and App IDs

```bash
./altsign-cli list --apple-id you@example.com --password 'your-password'
```

### Two-factor authentication

When 2FA is required, the tool prompts on stdin:

```
2FA verification required. Enter code: _
```

Enter the 6-digit code from your trusted device. The entire 2FA exchange completes within a single process — no re-authentication or cross-process state.

### All options

| Flag | Command | Description |
|------|---------|-------------|
| `--apple-id <email>` | all | Apple ID email |
| `--password <pwd>` | all | Apple ID password |
| `--udid <id>` | sign | Target device UDID |
| `--ipa <path>` | sign | Input IPA file |
| `--output <path>` | sign | Output path (default: `<input>_signed.ipa`) |
| `--bundle-id <id>` | sign | Override bundle identifier |
| `--verbose` | any | Print full API responses |

## Overview

Signing an IPA for sideloading requires several coordinated steps against Apple's backend:

1. **Authenticate** with Apple ID via the SRP protocol against `gsa.apple.com`, handling 2FA inline if needed
2. **Fetch a team** from Apple Developer Services — free accounts get a single personal team
3. **Resolve a signing certificate** — reuse an existing one (with saved private key) or create a new one by submitting a CSR
4. **Register the target device** UDID with the team
5. **Resolve an App ID** — look up the bundle identifier, create it if it doesn't exist
6. **Download a provisioning profile** that ties together the certificate, device, and App ID
7. **Re-sign the IPA** — embed the profile, extract entitlements, and sign all Mach-O binaries with `codesign`

The tool automates all of this in a single `sign` invocation.

## Design & Implementation

### Relationship to AltSign

This project would not exist without [AltSign](https://github.com/rileytestut/AltSign). The original AltSign library provided the reference implementation for:

- **SRP authentication** — the complete GSA protocol flow (init → challenge → complete → 2FA → token acquisition), including the `spd` decryption, negotiation proof HMAC, and the critical insight that 2FA must complete in a single process
- **Apple Developer Services API** — the dual-protocol design (Plist API vs Services API), URL structures, request/response formats, and authentication header requirements
- **Anisette data** — the approach of loading `AOSKit.framework` at runtime via `NSBundle` to obtain per-request OTP headers
- **Certificate lifecycle** — CSR generation, certificate parsing from Apple's response formats, and PKCS#12 packaging
- **Signing architecture** — the inside-out signing strategy (nested code first, app bundle last) and the provisioning profile embedding approach

Where this project departs from AltSign:

| | AltSign | altsign-cli |
|---|---|---|
| Signing backend | `ldid` C++ library (linked directly) | `codesign` CLI via temporary keychain |
| Runtime | iOS app (AltStore integration) | macOS CLI tool |
| Anisette fallback | AuthKit via XPC | `dlopen` + `dlsym` |
| CSR | SHA-1 signature | SHA-256 signature (OpenSSL 3.x EVP API) |
| P12 export | PEM cert storage, empty password | DER/PEM dual parsing, SHA-1 MAC forced for macOS compat |

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  main.mm — CLI entry point, argument parsing, flow orchestration │
├──────────────┬───────────────┬──────────────┬───────────────────┤
│  anisette.mm │  srp_auth.mm  │ apple_api.mm │    signer.mm      │
│  Anisette    │  SRP protocol │  Developer   │  IPA extraction,  │
│  data from   │  + 2FA +      │  Services    │  profile embed,   │
│  AOSKit      │  session      │  API client  │  P12/codesign,    │
│              │  persistence  │              │  repack           │
├──────────────┴───────────────┴──────────────┴───────────────────┤
│  certificate_request.mm — RSA 2048 keygen + X509 CSR (OpenSSL)  │
├─────────────────────────────────────────────────────────────────┤
│  Dependencies/corecrypto — Apple corecrypto headers (SRP math)  │
└─────────────────────────────────────────────────────────────────┘
```

### Authentication: SRP + 2FA

The tool implements Apple's GSA (Grand Slam) authentication protocol, which is based on SRP (RFC 5054 with Apple-specific modifications):

1. **SRP Init** — POST to `gsa.apple.com/grandslam/GsService2` with the user's Apple ID and a client public key (`A`). The request and response are XML plists.
2. **SRP Complete** — Process the server's challenge (`B`), compute the session key, verify the server proof (`M2`), and decrypt the speed-bag (`spd`) payload.
3. **2FA** (if triggered) — Apple responds with `hsc=409` and `au=secondaryAuth`. The tool sends a verification code to the user's trusted devices, reads the code from stdin, validates it, and then uses the original SRP session key to fetch the Xcode auth token.
4. **Token acquisition** — Exchange the SRP session for a `com.apple.gs.xcode.auth` token via the `apptokens` operation.

**Key constraint:** The entire 2FA flow must complete within a single process. Apple invalidates ephemeral OTP data across process boundaries, and re-authenticating after a successful 2FA validation causes Apple to return 409 again (infinite loop).

**Session caching:** Successful authentication is persisted to `~/Library/Application Support/altsign/session.plist`. Subsequent runs reuse the cached session.

### Anisette Data

Apple's authentication endpoints require Anisette headers — per-request OTP values tied to a hardware identity. The tool obtains these by loading `AOSKit.framework` at runtime via `NSBundle`.

### Apple Developer Services API

Apple exposes two distinct API protocols for developer services:

**Plist API** — used for teams, devices, CSR, App IDs, and provisioning profiles:
- Base URL: `developerservices2.apple.com/services/QH65B2/<action>`
- Body: XML plist, response: plist with `resultCode`

**Services API** — used for certificates:
- Base URL: `developerservices2.apple.com/services/v1/<path>`
- Body: JSON with `urlEncodedQueryParams`, response: JSON with `errors` array

### IPA Re-signing

The signing pipeline:

1. **Extract** the IPA via `ditto`
2. **Locate** the `.app` bundle and any `.appex`/`.xctest` extensions
3. **Rewrite** `CFBundleIdentifier` if `--bundle-id` is specified
4. **Embed** the provisioning profile as `embedded.mobileprovision`
5. **Parse** entitlements from the profile's embedded plist
6. **Generate a P12** — SHA-1 MAC forced via `PKCS12_set_mac` for macOS `security import` compatibility
7. **Sign inside-out**: sub-frameworks → frameworks → dylibs → extensions → app bundle, each via a temporary keychain + `codesign`
8. **Repack** into an IPA via `zip`

### Certificate Management

Free Apple Developer accounts are limited to one active iOS development certificate:

- **First run:** Generate RSA 2048 key, create CSR, submit to Apple, fetch the issued certificate, save private key to `~/Library/Application Support/altsign/keys/`
- **Subsequent runs:** Load existing certificate + saved private key
- **Key mismatch:** Revoke the old certificate and create a new one

### Known Limitations

- **macOS only** — Anisette data retrieval requires Apple's private frameworks (AOSKit/AuthKit)
- **7-day profile expiry** — free developer accounts' provisioning profiles expire after 7 days; re-sign to refresh
- **Bundle ID conflicts** — some bundle identifiers are globally registered by other developers; use `--bundle-id` to specify an alternative

## Acknowledgments

- [Riley Testut](https://github.com/rileytestut) for [AltSign](https://github.com/rileytestut/AltSign) and [AltStore](https://github.com/altstoreio/AltStore) — the protocol reference implementations this project is built upon
- [AltStore](https://github.com/altstoreio/AltStore) contributors for the Anisette data fetching and 2FA interaction patterns

## Disclaimer

This project is intended for educational purposes and personal use. It is not affiliated with or endorsed by Apple Inc. Use responsibly and in accordance with Apple's Developer Program License Agreement.
