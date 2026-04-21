#!/bin/bash
#
# build.sh — AltSign CLI 编译脚本
# 需要: macOS + Xcode CLT + OpenSSL 3.x (brew install openssl)
#

set -e

# 自动检测 OpenSSL 路径
if command -v brew &>/dev/null; then
    OPENSSL_PREFIX=$(brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo "/opt/homebrew/opt/openssl")
else
    OPENSSL_PREFIX="/opt/homebrew/opt/openssl"
fi

OUTPUT="altsign-cli"
SDK_PATH="$(xcrun --show-sdk-path)"
CORECRYPTO_DIR="Dependencies/corecrypto"

if [ ! -d "${CORECRYPTO_DIR}" ]; then
    echo "❌ Missing ${CORECRYPTO_DIR}. Please ensure corecrypto headers are available."
    exit 1
fi

echo "============================================"
echo " Building AltSign CLI"
echo " OpenSSL: ${OPENSSL_PREFIX}"
echo " SDK: ${SDK_PATH}"
echo "============================================"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

clang -ObjC -fobjc-arc \
    -DCORECRYPTO_DONOT_USE_TRANSPARENT_UNION \
    -I"Dependencies" \
    -isysroot "${SDK_PATH}" \
    -c "${CORECRYPTO_DIR}/ccsrp.m" \
    -o "${TMP_DIR}/ccsrp.o"

clang++ -std=c++17 -ObjC++ -fobjc-arc \
    -Wall -Wextra \
    -Wno-deprecated-declarations \
    -Wno-unused-parameter \
    -DCORECRYPTO_DONOT_USE_TRANSPARENT_UNION \
    -framework Foundation \
    -framework Security \
    -framework CoreFoundation \
    -I"${OPENSSL_PREFIX}/include" \
    -I"Dependencies" \
    -L"${OPENSSL_PREFIX}/lib" \
    -L"${SDK_PATH}/usr/lib/system" \
    -lssl -lcrypto -lcorecrypto \
    -o "${OUTPUT}" \
    main.mm \
    anisette.mm \
    srp_auth.mm \
    apple_api.mm \
    certificate_request.mm \
    signer.mm \
    "${TMP_DIR}/ccsrp.o"

echo "============================================"
echo " ✅ Build successful: ./${OUTPUT}"
echo "============================================"
echo ""
echo "Usage:"
echo "  ./${OUTPUT} sign --apple-id user@example.com --password 'xxx' \\"
echo "                   --udid 00008030-000000000000 --ipa ./MyApp.ipa"
echo ""
echo "  ./${OUTPUT} cert --apple-id user@example.com --password 'xxx'"
