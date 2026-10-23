#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
clang++ -std=c++17 -fobjc-arc -Wall -Wextra -Wno-unused-parameter \
  -framework Foundation tests/test_anisette.mm anisette.mm diagnostics.mm -o "$TEST_ROOT/test"
if [[ "${1:-}" == "--live" ]]; then
  export ALTSIGN_ANISETTE_SERVER="${ALTSIGN_ANISETTE_SERVER:-https://mac-ani.jkcoxson.com}"
fi
HOME="$TEST_ROOT" CFFIXED_USER_HOME="$TEST_ROOT" TMPDIR="$TEST_ROOT" "$TEST_ROOT/test" "$@"
