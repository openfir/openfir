[![DOI](https://zenodo.org/badge/1460848493.svg)](https://doi.org/10.5281/zenodo.24297603)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

# OpenFIR (`openfir`) v1.0

**OpenFIR** (**Open** **F**ast **I**nterleaved **R**eliable Transport Protocol) is an open, standards-aligned, bidirectional (`push` & `pull`), enterprise-grade **pure file and directory transfer engine** written in Go under the **Apache License 2.0**.

Engineered for high Bandwidth-Delay Product (BDP) wide-area networks, transcontinental links, satellite backhauls, and ISP UDP-policed environments, OpenFIR v1.0 combines **standard RFC 8446 TLS 1.3 (`ALPN: openfir/1`)** with a **transparent, open-header UDP acceleration lane (`OF1\x01`, Linux `UDP_SEGMENT` GSO + `UDP_GRO`)**, **clean-room 1981 Rabin polynomial Content-Defined Chunking (CDC)** with exact 0%-false-positive cross-session CAS, **clean-room systematic Cauchy GF(256) Reed-Solomon FEC** (0% loss = strictly 0% overhead), **rate-invariant Kalman delay-gradient congestion control**, **streaming BLAKE2b-256 binary Merkle verification**, **tarless `VirtualDirectoryExtent` directory streaming**, and **persistent crash-resumable staging**.

> **Supply-Chain & Legal Purity**: OpenFIR v1.0 has **zero third-party GitHub module dependencies**. Compiled binaries link exclusively against the **Go Standard Library** and the official Go project extension modules **`golang.org/x/crypto`** and **`golang.org/x/sys`**. Every transport, chunking, compression, erasure-coding, and congestion-control algorithm is either a clean-room original implementation of >25-year public-domain mathematics, a CC0 public-domain primitive, or an open royalty-free IETF/NIST RFC standard.

---

## Upgrading from Legacy `v0.x` (Breaking Wire Change)

`v1.0.0` is a ground-up architectural rewrite establishing the stable `openfir/1` protocol specification:

| Subsystem | Legacy `v0.x` (Deprecated Experimental) | Stable `v1.0.0` (Current) |
| :--- | :--- | :--- |
| **Transport & Firewall Compliance** | Pure UDP only; custom 6B ASCII header + 12MB port rotation + 4-port matrix | **Single-Port Dual-Stack (`:443` / `:9900`)**: Standard **RFC 8446 TLS 1.3 (`ALPN: openfir/1`)** control & parallel TCP data lanes + transparent **`OF1\x01`** 17B AAD UDP data lane |
| **ISP UDP QoS / Blackhole Defense** | Stalls when UDP is blocked or throttled across an IP | **Hybrid UDP + Multi-Stream TLS 1.3 TCP Scheduler**: Sub-second automatic failover when UDP is blocked from packet #0 or blackholed mid-stream |
| **Chunking, CAS & Verification** | 1,200B fixed chunks (0% reuse on 1B insert) + 8,192-bit Bloom (saturates at ~10MB) + upfront full-disk SHA-256 stall | **0ms Cold-Start 1981 Rabin Polynomial CDC** (48B sliding window, >98% 1-byte shift immunity) + **Exact 0%-FP Interactive TLS CAS** + **Streaming Binary Merkle Tree (BLAKE2b-256)** |
| **Forward Error Correction** | GF(2) 4-XOR + 5% cruise overhead on clean links | **Clean-Room Cauchy GF(256) Reed-Solomon**: **0% loss = strictly 0% parity overhead**; recovers contiguous multi-packet burst drops in a single solve |
| **Congestion Control** | 50 MiB/s cold start + raw µs delta + hardcoded 20ms retx cooldown + 8MB burst | **Delay-Gradient & Delivery-Rate CC**: Safe 4 MiB/s RFC 5681 Slow Start + **RFC 6298 `SRTT`** + **dynamic `max(1.25×SRTT+RTTvar, 25ms)` cooldown** + **normalized 1960 Kalman OWDG** + **CAR-safe ≤256KB burst** |
| **Compression & Kernel NetIO** | Uncompressed single-packet syscalls | **Entropy-Gated RFC 1951 DEFLATE (`compress/flate`, 4KB sample bypass) + All-Zero Sentinel** + **Linux `UDP_SEGMENT` (GSO) / `UDP_GRO` (`ReadBatchGRO`) / `SO_REUSEPORT`** + **Windows `timeBeginPeriod(1)`** |
| **Direction & Resumability** | Push-only; staging deleted on 25s timeout | **Bidirectional `push` & `pull`** + **Persistent `.openfir-part` / `.openfir-state` Crash-Resume** across disconnects & server restarts |
| **Authentication & KDF** | Single HKDF on `pass:` | **Argon2id (RFC 9106, 32 MiB)** + **TLS 1.3 RFC 5705 `ExportKeyingMaterial` Channel-Bound Mutual Auth** + **Ephemeral X25519 PFS AES-256-GCM** |

> Both server and client must run `v1.0.0+`. Historical `v0.1.0 ~ v0.7.0` source history and tags are preserved untouched for auditability (`legacy/v0.7` archive branch).

---

## Core Architecture

```text
+------------------------------------------------------------------------------------+
|                              OpenFIR v1.0 SENDER                                   |
|                                                                                    |
|  [File OR Directory Tree] -> [VirtualDirectoryExtent (O(log N), 64-FD LRU)]        |
|                                        |                                           |
|                                        v                                           |
|      [0ms Cold-Start 1981 Rabin Polynomial CDC (48B Window, BLAKE2b-256)]          |
|                     |                                     |                        |
|        (Streaming Merkle Tree)           (Interactive TLS 1.3 CAS / Resume Query)  |
|                                               /           |            \           |
|                                    (CAS/Resume Hit)  (All-Zero)     (New Block)    |
|                                          |                |              v         |
|                                      [0 Wire B]    [MsgZeroBlock] [4KB Entropy-    |
|                                                                    Gated DEFLATE]  |
|                                                                          |         |
|                                       [Hybrid Anti-QoS Path Scheduler] <-+         |
|                                        /                            \              |
|               (Healthy High-BDP Link) /                              \ (Fallback / |
|                                      v                                v Parallel)  |
|        [Clean-Room Cauchy GF(256) RS (0% loss = 0 parity)]   [K Parallel TLS 1.3   |
|         -> [Delay-Gradient & CAR-Safe MicroPacer (<=256KB)]   TCP Data Lanes]      |
|         -> [OF1\x01 17B AAD + X25519-PFS AES-256-GCM]                |             |
|         -> [Linux UDP_SEGMENT GSO Batch Writer]                      |             |
+--------------------------------------|-------------------------------|-------------+
                                       | Single Port (:443 / :9900)    |
                    UDP (OF1\x01)      v                               v  TCP (TLS 1.3 ALPN openfir/1)
+--------------------------------------|-------------------------------|-------------+
|                              OpenFIR v1.0 RECEIVER                   |             |
|                                      |                               |             |
|   [Linux UDP_GRO ReadBatchGRO + 16,384-Pkt Replay Window]            |             |
|    -> [Cauchy GF(256) RS Decoder + Normalized Kalman OWDG]           |             |
|                                       \                             /              |
|                                        v                           v               |
|           [BLAKE2b-256 Block Verify + Persistent .openfir-part/.openfir-state]     |
|                                        |                                           |
|                                        v                                           |
|       [Streaming Binary Merkle Root Verify -> fsync -> Atomic Commit / Unpack]     |
+------------------------------------------------------------------------------------+
```

---

## Open Wire Specification (`openfir/1`)

OpenFIR v1.0 uses strictly transparent, Wireshark- and enterprise-firewall-friendly framing with **zero protocol spoofing or port-hopping obfuscation**:

1. **Control & Parallel TCP Data Lanes**: Standard **RFC 8446 TLS 1.3** over TCP advertising **`ALPN: openfir/1`**, authenticated mutually via **RFC 5705 `ExportKeyingMaterial`** (`EXPORTER-OpenFIR-v1-ChannelBind`), binding the shared secret cryptographically to the live TLS 1.3 handshake to defeat active MITM even when using ephemeral self-signed certificates.
2. **UDP Data Lane** (33 bytes total overhead: 17-byte cleartext AAD header + 16-byte AES-256-GCM tag):
   ```text
   +-------------------+-----------+---------------+------------------+------------------------+
   | Magic "OF1\x01"   | Flags(1B) | SessionID(4B) | MonotonicSeq(8B) | AES-256-GCM Cipher+Tag |
   +-------------------+-----------+---------------+------------------+------------------------+
   |<----------------------------- 17-Byte AAD ----------------------->|
   ```
   * Per-session directional `c2s`/`s2c` AES-256-GCM keys and 4-byte nonce salts are derived from `HKDF-SHA256(MasterKey || EphemeralX25519SharedSecret, SessionID)`.
   * Nonce is `DirSalt(4B) || MonotonicSeq(8B)`; inbound packets pass a **16,384-packet sliding anti-replay bitmap**.

---

## Quick Start

### Install / Build from Source (Go 1.26+)

```bash
# Install directly via Go modules
go install github.com/openfir/openfir/cmd/openfir@v1.0.0

# Or build locally from a cloned repository
go build -trimpath -ldflags="-s -w" -o bin/openfir ./cmd/openfir
```

### 1. Run Built-In Enterprise Self-Test (`selftest` mode)
Validates 4 end-to-end suites locally: (1) 4 MiB mixed-entropy Hybrid Auto Push & Bidirectional Pull (`FECParity=0`); (2) 17-byte prepended shift-resistant Rabin CDC CAS teleportation; (3) 10% 4-packet contiguous burst-loss pure UDP recovery with clean-room Cauchy GF(256) RS; (4) mid-stream 100% ISP UDP blackhole seamless failover to multi-stream TLS 1.3 TCP.

```bash
./bin/openfir -mode selftest
```

### 2. Production Server, Push & Pull

```bash
# 1. Generate a 256-bit shared secret key
export OPENFIR_SECRET=$(./bin/openfir -mode keygen)

# 2. Start Single-Port Dual-Stack Server (TLS 1.3 TCP + UDP on :443 or :9900)
#    (Optional: pass -tls-cert / -tls-key for a CA-signed domain certificate)
./bin/openfir -mode server -listen :443 -dir ./openfir_data -secret "$OPENFIR_SECRET" \
  -tls-cert /etc/ssl/fullchain.pem -tls-key /etc/ssl/privkey.pem

# 3. Push a file OR entire nested directory tree (Hybrid Auto: UDP GSO/FEC + TLS 1.3 TCP)
./bin/openfir -mode push -server files.example.com:443 -verify-ca \
  -file ./large_dataset -secret "$OPENFIR_SECRET"

# 4. Pull a file OR directory tree back from server
./bin/openfir -mode pull -server files.example.com:443 -verify-ca \
  -file large_dataset -dir ./downloads -secret "$OPENFIR_SECRET"
```

---

## Command-Line Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-mode` | `""` | Execution mode: `server`, `push`, `pull`, `keygen`, or `selftest` |
| `-listen` | `:9900` | Single-port dual-stack (TLS 1.3 TCP + UDP) server listen address (e.g., `:443`) |
| `-server` | `127.0.0.1:9900` | Target server address for `push` / `pull` |
| `-sni` | *(host from `-server`)* | Optional TLS 1.3 SNI hostname |
| `-verify-ca` | `false` | Enforce system/public CA certificate verification (recommended with `-tls-cert`) |
| `-tls-cert` / `-tls-key` | `""` | Server TLS 1.3 certificate & private key PEM paths (auto-generates ephemeral ECDSA P-256 cert if omitted) |
| `-dir` | `./openfir_data` | Server root directory (`server`) OR local output directory (`pull`) |
| `-file` | `""` | Local file/directory path (`push`) OR remote file/directory name (`pull`) |
| `-name` | *(basename of `-file`)* | Optional remote filename override for `push` |
| `-secret` | `$OPENFIR_SECRET` | Shared secret: 64-char hex (256-bit) or `pass:<passphrase>` (Argon2id 32 MiB) |
| `-transport` | `auto` | Data-plane mode: `auto` (Hybrid UDP + TLS 1.3 TCP), `udp`, or `tcp` |
| `-tcp-streams` | `4` | Parallel TLS 1.3 TCP data lanes for `auto` / `tcp` modes |
| `-init-mbps` | `4.0` | Initial slow-start pacing rate in MiB/s |
| `-max-mbps` | `1000.0` | Maximum pacing rate ceiling in MiB/s |
| `-max-parity` | `8` | Max Cauchy GF(256) RS parity shards per 16-shard group (0% loss = strictly 0 parity) |
| `-overwrite` | `false` | Allow overwriting existing destination files or directories |
| `-max-file-gb` | `256` | Maximum allowed transfer size in GB on server |
| `-max-sessions` | `64` | Maximum concurrent active sessions on server |

---

## All-Platform Native Frosted-Glass Clients (*Obsidian Frost × Neon Aurora*)

All six OpenFIR clients share a unified modern Web3 frosted-glass design language ([`design/DESIGN_SYSTEM.md`](design/DESIGN_SYSTEM.md)) and link directly in-process to the Apache-2.0 OpenFIR C ABI core ([`include/openfir.h`](include/openfir.h)) with **zero third-party UI frameworks or external dependencies**:

| Platform | Binary / Package | Native Language & Graphics Stack | Frosted-Glass Engine | Third-Party UI Deps |
| :--- | :--- | :--- | :--- | :---: |
| **Linux CLI (TUI)** | `openfir-tui` | **Pure C11** (`termios`, `ioctl`, SGR 1006 mouse, DEC 2026 sync) | 24-bit TrueColor spatial-blur alpha-blended glass cards + 2×4 Unicode Braille sparklines over animated aurora | **0** (no `ncurses`) |
| **Linux Desktop** | `openfir-gui` | **Pure C++20** + raw **X11 (`libX11`) + `libXft`** | Custom ARGB32 2-pass separable Gaussian-blur frosted glass compositor + SDF neon geometry | **0** (no GTK/Qt/Electron) |
| **Windows x64** | `OpenFIR.exe` | **Pure C++20** + **Win32 + Direct2D + DirectWrite + DWM** | Native Windows 11 DWM Acrylic (`DWMWA_SYSTEMBACKDROP_TYPE`) + GPU Direct2D translucent glass & sparklines | **0** (Win32 SDK only) |
| **macOS 13+** | `OpenFIR.app` | **Pure Swift** + **AppKit (`NSVisualEffectView`) + SwiftUI** | Native macOS `.hudWindow` system vibrancy over animated `Canvas` aurora + `NSOpenPanel` | **0** (Apple SDK only) |
| **iOS 15.0+** | `OpenFIR-iOS.ipa` | **Pure Swift** + **SwiftUI + UIKit (`.ultraThinMaterial`)** | Native iOS ultra-thin frosted glass material + Files `fileImporter` integration | **0** (Apple SDK only) |
| **Android 8–15+** | `OpenFIR-Android.apk` | **Pure Kotlin** + **Android Platform SDK + C11 JNI** | Native Android 12+ GPU `RenderEffect.createBlurEffect` + custom hardware-accelerated `Canvas` glass | **0** (no AndroidX/Material/Compose) |

### Local Build Examples (Linux)
```bash
# 1. Build zero-dependency OpenFIR C ABI core library
CGO_ENABLED=1 go build -trimpath -buildmode=c-shared \
  -ldflags="-s -w -extldflags=-Wl,-soname,libopenfir_core.so" \
  -o dist/libopenfir_core.so ./cmd/openfir-cabi

# 2. Build & verify Pure C11 Linux Frosted-Glass TUI (zero ncurses)
make -C apps/linux-tui test

# 3. Build & verify Pure C++20 Linux X11 Gaussian-Blur GUI (zero GTK/Qt)
make -C apps/linux-gui test
```

---

## Clean-Room Provenance, IP Purity & Legal Compliance

### 1. Patent-Free & Public-Domain Algorithm Provenance
Every core mechanism in OpenFIR v1.0 was intentionally selected and clean-room implemented to eliminate third-party patent encumbrances and copyleft obligations:

| Component | Algorithm / Standard | Origin & Public-Domain / Open-Standard Basis |
| :--- | :--- | :--- |
| **Control & TCP Transport** | TLS 1.3 (`ALPN: openfir/1`) & Channel Binding | IETF RFC 8446 & RFC 5705 (Go stdlib `crypto/tls`) |
| **AEAD & Forward Secrecy** | AES-256-GCM & X25519 ECDH | NIST SP 800-38D & IETF RFC 7748 (Go stdlib `crypto/aes`, `crypto/cipher`, `crypto/ecdh`) |
| **Password KDF & Block Hash** | Argon2id & BLAKE2b-256 | IETF RFC 9106 & RFC 7693 — released under **CC0 Public Domain** (`golang.org/x/crypto`, BSD-3-Clause + Google `PATENTS` grant) |
| **Content-Defined Chunking** | Classic Rabin Polynomial Rolling Fingerprint (48B window, single power-of-2 mask) | Michael O. Rabin (1981) & LBFS single-mask CDC (2001) — >25-year public-domain prior art; original degree-53 irreducible polynomial `0x003614c8012bce63` derived deterministically via SHA-256 |
| **End-to-End Integrity** | Binary Merkle Tree over BLAKE2b-256 | Ralph Merkle (1979, patent expired 2002) — clean-room Go implementation |
| **Forward Error Correction** | Systematic Cauchy GF(256) Reed-Solomon (`0x11D`) | Reed & Solomon (1960) & Blomer et al. Cauchy construction (1995) — >30-year textbook math, clean-room Go implementation with zero external libraries |
| **Adaptive Compression** | Entropy-Gated RFC 1951 DEFLATE (`BestSpeed`) | IETF RFC 1951 (1993) — >30-year public-domain standard (Go stdlib `compress/flate`) |
| **Congestion Control** | Delay-Gradient & Delivery-Rate CC | RFC 5681 slow start, RFC 6298 SRTT, Kalman filter (1960), and token-bucket pacing — clean-room Go implementation |
| **Kernel Offloads** | `UDP_SEGMENT` (GSO), `UDP_GRO`, `SO_REUSEPORT`, `timeBeginPeriod` | Standard public Linux/Windows OS kernel ABI (`golang.org/x/sys`, BSD-3-Clause + Google `PATENTS` grant) |

### 2. Defensive Publication & Prior Art Notice
This repository and its Zenodo-archived DOI releases ([`10.5281/zenodo.24297603`](https://doi.org/10.5281/zenodo.24297603)) serve as an open technical reference and defensive publication of the OpenFIR protocol architecture under the Apache License 2.0.

### 3. Third-Party Dependency Attribution & Binary Redistribution
OpenFIR v1.0 has **zero third-party GitHub dependencies**. Its only external build dependencies are the Go Standard Library and the official `golang.org/x/crypto` and `golang.org/x/sys` modules (all **BSD-3-Clause** + Go Project **Additional IP Rights Grant (Patents)**). Complete verbatim third-party copyright and license notices are provided in [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) and bundled in every official release archive alongside [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

### 4. Cryptography & Export Control Notice
This repository utilizes standard `TLS 1.3`, `AES-256-GCM`, `X25519` (`crypto/ecdh`), `ECDSA P-256`, `HMAC-SHA256`, `SHA-256`, `Argon2id`, and `BLAKE2b-256` from the Go standard library and official `golang.org/x/crypto` packages for authenticated transport security, forward-secret key agreement, and cryptographic data integrity. This software is publicly available open-source encryption source code eligible for License Exception **TSU / EAR § 742.15(b)** under the U.S. Export Administration Regulations.

### 5. Trademark & Warranty Disclaimer
All third-party product, protocol, or operating-system names mentioned in this documentation (such as Linux, Windows, macOS, Wireshark, or Let's Encrypt) are used strictly for descriptive compatibility reference and remain the property of their respective owners. This software is provided **"AS IS"**, without warranty of any kind, express or implied, as set forth in Sections 7 and 8 of the Apache License 2.0. Nothing in this repository constitutes legal advice.

---

## License

Copyright (c) 2026 The OpenFIR Authors (`openfir`). All rights reserved.

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), and [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) files for full terms and third-party attributions.
