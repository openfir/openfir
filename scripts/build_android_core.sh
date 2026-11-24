#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds Android JNI shared libraries (`libopenfir_core.so`) for arm64-v8a and x86_64
# with DT_SONAME="libopenfir_core.so" directly from the zero-third-party-dep Go core.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist/android/jniLibs"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

if [ -z "${NDK}" ] || [ ! -d "${NDK}" ]; then
  echo "ERROR: ANDROID_NDK_HOME or ANDROID_NDK_ROOT must point to Android NDK" >&2
  exit 1
fi

HOST_TAG="linux-x86_64"
if [ "$(uname -s)" = "Darwin" ]; then
  HOST_TAG="darwin-x86_64"
fi
TOOLCHAIN="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}/bin"

mkdir -p "${OUT_DIR}/arm64-v8a" "${OUT_DIR}/x86_64"

echo "[1/2] Building Android arm64-v8a libopenfir_core.so..."
(cd "${ROOT_DIR}" && \
  CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  CC="${TOOLCHAIN}/aarch64-linux-android26-clang" \
  go build -trimpath -buildmode=c-shared \
  -ldflags="-s -w -extldflags=-Wl,-soname,libopenfir_core.so" \
  -o "${OUT_DIR}/arm64-v8a/libopenfir_core.so" ./cmd/openfir-cabi)

echo "[2/2] Building Android x86_64 libopenfir_core.so..."
(cd "${ROOT_DIR}" && \
  CGO_ENABLED=1 GOOS=android GOARCH=amd64 \
  CC="${TOOLCHAIN}/x86_64-linux-android26-clang" \
  go build -trimpath -buildmode=c-shared \
  -ldflags="-s -w -extldflags=-Wl,-soname,libopenfir_core.so" \
  -o "${OUT_DIR}/x86_64/libopenfir_core.so" ./cmd/openfir-cabi)

rm -f "${OUT_DIR}/arm64-v8a/libopenfir_core.h" "${OUT_DIR}/x86_64/libopenfir_core.h"
ls -lh "${OUT_DIR}/arm64-v8a/libopenfir_core.so" "${OUT_DIR}/x86_64/libopenfir_core.so"
