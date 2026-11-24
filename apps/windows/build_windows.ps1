# SPDX-License-Identifier: Apache-2.0
# Builds OpenFIR Windows x64 `openfir_core.dll` (Go C-ABI) + pure C++20 Direct2D/DWM Acrylic `OpenFIR.exe`.
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$OutDir = Join-Path $Root "dist\windows"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Push-Location $Root
try {
    Write-Host "[1/3] Building openfir_core.dll (Go C-ABI, zero third-party deps)..."
    $env:CGO_ENABLED = "1"
    go build -trimpath -buildmode=c-shared -ldflags="-s -w" -o (Join-Path $OutDir "openfir_core.dll") ./cmd/openfir-cabi

    Write-Host "[2/3] Building openfir.exe CLI..."
    $env:CGO_ENABLED = "0"
    go build -trimpath -ldflags="-s -w" -o (Join-Path $OutDir "openfir.exe") ./cmd/openfir

    Write-Host "[3/3] Compiling OpenFIR.exe (Pure C++20 Win32 + Direct2D + DirectWrite + DWM Acrylic)..."
    $Src = Join-Path $Root "apps\windows\openfir_win.cpp"
    $Exe = Join-Path $OutDir "OpenFIR.exe"
    cl.exe /nologo /std:c++20 /O2 /EHsc /W4 /DUNICODE /D_UNICODE $Src `
        /Fe:$Exe /link /SUBSYSTEM:WINDOWS d2d1.lib dwrite.lib dwmapi.lib user32.lib gdi32.lib ole32.lib shell32.lib comdlg32.lib

    Copy-Item LICENSE, NOTICE, THIRD_PARTY_LICENSES.md, README.md $OutDir
    Write-Host "[Done] Built Windows Frosted-Glass GUI bundle in $OutDir"
} finally {
    Pop-Location
}
