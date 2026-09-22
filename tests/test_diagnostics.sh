#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
SDK_PATH="$(xcrun --show-sdk-path)"
clang -ObjC -fobjc-arc -DCORECRYPTO_DONOT_USE_TRANSPARENT_UNION \
  -IDependencies -isysroot "$SDK_PATH" -c Dependencies/corecrypto/ccsrp.m -o "$TEST_ROOT/ccsrp.o"
clang++ -std=c++17 -fobjc-arc -Wno-deprecated-declarations \
  -DCORECRYPTO_DONOT_USE_TRANSPARENT_UNION -IDependencies \
  -framework Foundation -L"$SDK_PATH/usr/lib/system" -lcorecrypto \
  tests/test_diagnostics.mm anisette.mm diagnostics.mm "$TEST_ROOT/ccsrp.o" -o "$TEST_ROOT/test"
HOME="$TEST_ROOT" CFFIXED_USER_HOME="$TEST_ROOT" TMPDIR="$TEST_ROOT" "$TEST_ROOT/test"
