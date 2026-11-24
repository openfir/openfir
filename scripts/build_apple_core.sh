#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds OpenFIRCore.xcframework (macOS universal arm64+x86_64 & iOS 15.0+ arm64)
# directly from the zero-third-party-dependency Go core via -buildmode=c-archive.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/apple"
STAGE="${OUT_DIR}/stage"
rm -rf "${STAGE}" "${OUT_DIR}/OpenFIRCore.xcframework"
mkdir -p "${STAGE}/macos" "${STAGE}/ios" "${STAGE}/headers"

cp "${ROOT_DIR}/include/openfir.h" "${STAGE}/headers/openfir.h"
cat > "${STAGE}/headers/module.modulemap" <<'EOF'
module OpenFIRCore {
    header "openfir.h"
    export *
}
EOF

echo "[1/3] Building macOS arm64 + x86_64 libopenfir_core.a..."
MACOS_SDK="$(xcrun --sdk macosx --show-sdk-path)"
MACOS_CC="$(xcrun --sdk macosx --find clang)"

(cd "${ROOT_DIR}" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
  CC="${MACOS_CC} -isysroot ${MACOS_SDK} -arch arm64 -mmacosx-version-min=13.0" \
  CGO_CFLAGS="-isysroot ${MACOS_SDK} -arch arm64 -mmacosx-version-min=13.0" \
  go build -trimpath -buildmode=c-archive -ldflags="-s -w" \
  -o "${STAGE}/macos/libopenfir_core_arm64.a" ./cmd/openfir-cabi)

(cd "${ROOT_DIR}" && \
  CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
  CC="${MACOS_CC} -isysroot ${MACOS_SDK} -arch x86_64 -mmacosx-version-min=13.0" \
  CGO_CFLAGS="-isysroot ${MACOS_SDK} -arch x86_64 -mmacosx-version-min=13.0" \
  go build -trimpath -buildmode=c-archive -ldflags="-s -w" \
  -o "${STAGE}/macos/libopenfir_core_x86_64.a" ./cmd/openfir-cabi)

lipo -create \
  "${STAGE}/macos/libopenfir_core_arm64.a" \
  "${STAGE}/macos/libopenfir_core_x86_64.a" \
  -output "${STAGE}/macos/libopenfir_core.a"

echo "[2/3] Building iOS 15.0+ arm64 libopenfir_core.a..."
IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
IOS_CC="$(xcrun --sdk iphoneos --find clang)"

(cd "${ROOT_DIR}" && \
  CGO_ENABLED=1 GOOS=ios GOARCH=arm64 \
  CC="${IOS_CC} -isysroot ${IOS_SDK} -arch arm64 -miphoneos-version-min=15.0" \
  CGO_CFLAGS="-isysroot ${IOS_SDK} -arch arm64 -miphoneos-version-min=15.0" \
  go build -trimpath -buildmode=c-archive -ldflags="-s -w" \
  -o "${STAGE}/ios/libopenfir_core.a" ./cmd/openfir-cabi)

echo "[3/3] Creating OpenFIRCore.xcframework..."
xcodebuild -create-xcframework \
  -library "${STAGE}/macos/libopenfir_core.a" -headers "${STAGE}/headers" \
  -library "${STAGE}/ios/libopenfir_core.a"   -headers "${STAGE}/headers" \
  -output "${OUT_DIR}/OpenFIRCore.xcframework"

rm -rf "${STAGE}"
echo "Done: ${OUT_DIR}/OpenFIRCore.xcframework"
