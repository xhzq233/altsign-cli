#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd -P)"
BIN="${1:-$ROOT_DIR/altsign-cli}"

if [[ ! -x "$BIN" ]]; then
  echo "[altsign-test] executable is unavailable: $BIN" >&2
  exit 1
fi

TEST_HOME="$(mktemp -d "${TMPDIR:-/tmp}/altsign-contract.XXXXXX")"
cleanup() {
  /bin/rm -rf -- "$TEST_HOME"
}
trap cleanup EXIT

run_with_home() {
  TMPDIR="$TEST_HOME" CFFIXED_USER_HOME="$TEST_HOME" HOME="$TEST_HOME" "$BIN" "$@"
}

if run_with_home current-account >"$TEST_HOME/current.out" 2>"$TEST_HOME/current.err"; then
  echo "[altsign-test] removed current-account command unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q "Unknown command: current-account" "$TEST_HOME/current.err"; then
  echo "[altsign-test] removed current-account command is still recognized" >&2
  exit 1
fi
if [[ -e "$TEST_HOME/Library/Application Support/altsign" ]]; then
  echo "[altsign-test] invalid command created session storage" >&2
  exit 1
fi

if run_with_home sign --password secret --udid test --ipa test.ipa \
    >"$TEST_HOME/password.out" 2>"$TEST_HOME/password.err"; then
  echo "[altsign-test] password argv unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q -- "--password is not supported" "$TEST_HOME/password.err"; then
  echo "[altsign-test] password argv rejection is unclear" >&2
  exit 1
fi

if run_with_home list --unknown value \
    >"$TEST_HOME/unknown.out" 2>"$TEST_HOME/unknown.err"; then
  echo "[altsign-test] unknown option unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q "unknown option for list" "$TEST_HOME/unknown.err"; then
  echo "[altsign-test] unknown-option error is unclear" >&2
  exit 1
fi

if run_with_home list --apple-id first@example.invalid \
    --apple-id second@example.invalid \
    >"$TEST_HOME/duplicate.out" 2>"$TEST_HOME/duplicate.err"; then
  echo "[altsign-test] duplicate option unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q "duplicate option: --apple-id" "$TEST_HOME/duplicate.err"; then
  echo "[altsign-test] duplicate-option error is unclear" >&2
  exit 1
fi

if run_with_home list --apple-id \
    >"$TEST_HOME/missing-value.out" 2>"$TEST_HOME/missing-value.err"; then
  echo "[altsign-test] missing option value unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q -- "--apple-id requires a value" "$TEST_HOME/missing-value.err"; then
  echo "[altsign-test] missing-value error is unclear" >&2
  exit 1
fi

if run_with_home list --apple-id --verbose \
    >"$TEST_HOME/option-value.out" 2>"$TEST_HOME/option-value.err"; then
  echo "[altsign-test] option-looking value unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q -- "--apple-id requires a value" "$TEST_HOME/option-value.err"; then
  echo "[altsign-test] option-looking value was not rejected" >&2
  exit 1
fi

start_seconds="$SECONDS"
if run_with_home list --apple-id contract@example.invalid </dev/null \
    >"$TEST_HOME/no-tty.out" 2>"$TEST_HOME/no-tty.err"; then
  echo "[altsign-test] EOF on standard input unexpectedly succeeded" >&2
  exit 1
fi
if (( SECONDS - start_seconds > 2 )); then
  echo "[altsign-test] no-TTY authentication did not fail quickly" >&2
  exit 1
fi
if ! /usr/bin/grep -Eq "standard input|password was not provided" "$TEST_HOME/no-tty.err"; then
  echo "[altsign-test] stdin EOF error is unclear" >&2
  exit 1
fi

if /usr/bin/printf '\n' | run_with_home list --apple-id contract@example.invalid \
    >"$TEST_HOME/pipe.out" 2>"$TEST_HOME/pipe.err"; then
  echo "[altsign-test] empty piped password unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q "password was not provided" "$TEST_HOME/pipe.err"; then
  echo "[altsign-test] piped stdin did not use the password reader" >&2
  exit 1
fi

SESSION_DIR="$TEST_HOME/Library/Application Support/altsign"
/bin/mkdir -p "$SESSION_DIR"
/bin/chmod 700 "$SESSION_DIR"
/usr/bin/python3 - "$SESSION_DIR/session.plist" <<'PY'
import datetime
import plistlib
import sys

path = sys.argv[1]
session = {
    "appleID": "single@example.invalid",
    "dsid": "12345",
    "authToken": "test-token",
    "expirationDate": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=1),
    "anisetteData": {},
}
with open(path, "wb") as stream:
    plistlib.dump(session, stream)
PY
/bin/chmod 600 "$SESSION_DIR/session.plist"

if run_with_home sign --udid test \
    >"$TEST_HOME/single.out" 2>"$TEST_HOME/single.err"; then
  echo "[altsign-test] incomplete sign unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q -- "--udid and one of --ipa/--app are required" "$TEST_HOME/single.err"; then
  echo "[altsign-test] sign did not load the single cached session" >&2
  exit 1
fi

if [[ "$(/usr/bin/stat -f '%Lp' "$SESSION_DIR")" != "700" ||
      "$(/usr/bin/stat -f '%Lp' "$SESSION_DIR/session.plist")" != "600" ]]; then
  echo "[altsign-test] session storage permissions are not owner-only" >&2
  exit 1
fi

/usr/bin/python3 - "$SESSION_DIR/session.plist" <<'PY'
import plistlib
import sys

path = sys.argv[1]
with open(path, "rb") as stream:
    root = plistlib.load(stream)
root["expirationDate"] = "not-a-date"
with open(path, "wb") as stream:
    plistlib.dump(root, stream)
PY
/bin/chmod 600 "$SESSION_DIR/session.plist"
if run_with_home sign --udid test \
    >"$TEST_HOME/malformed.out" 2>"$TEST_HOME/malformed.err"; then
  echo "[altsign-test] malformed cached session unexpectedly succeeded" >&2
  exit 1
fi
if ! /usr/bin/grep -q "no valid cached session" "$TEST_HOME/malformed.err"; then
  echo "[altsign-test] malformed session error is unclear" >&2
  exit 1
fi

echo "[altsign-test] CLI/session contract passed"
