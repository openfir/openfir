[![DOI](https://zenodo.org/badge/1460848493.svg)](https://doi.org/10.5281/zenodo.24297603)
# OpenFIR (`openfir`)

**OpenFIR** (**Open** **F**ast **I**nterleaved **R**eliable Transport Protocol) is a high-performance, multi-path, delay-gradient controlled, algebraically self-healing UDP file and directory transfer engine written in pure Go with zero external dependencies.

Engineered for high Bandwidth-Delay Product (BDP) wide-area networks, transcontinental links, satellite backhauls, and lossy wireless channels, OpenFIR decouples congestion control from random packet loss while eliminating retransmission round-trip penalties through coprime-stride erasure interleaving, in-flight content-addressed zero-byte teleportation, zero-RTT virtual continuous directory extents, and multi-socket 5-tuple striping.

---

## Core Architectural Innovations

### 1. $\phi$-Parity Coprime-Stride Interleaving & Belief-Propagation Peeling Decoder
Conventional Forward Error Correction (FEC) schemes group contiguous packets into block parity equations, which fail when network links experience Gilbert-Elliott contiguous burst losses.
* **Coprime Stride Interleaving:** OpenFIR weaves GF(2) algebraic parity equations (`PKT_PHI_PARITY`) across non-adjacent chunks separated by a coprime stride $S$ within a sliding window $W$. Any contiguous burst loss of up to $S$ packets impacts at most **one** symbol per algebraic equation.
* **Real-Time Iterative Peeling Decoder:** The receiver maintains an in-memory bipartite graph of pending parity equations backed by an L1 chunk ring cache. When an incoming data chunk or parity frame reduces an equation's unknown degree to $1$, the receiver immediately reconstructs the missing chunk via $O(1)$ XOR elimination and triggers an iterative breadth-first cascade across dependent equations—healing lost packets locally without waiting for a NACK Round-Trip Time (RTT).

### 2. In-Flight Content-Addressed Zero-Byte Teleportation (`PKT_TELEPORT`)
Real-world datasets—such as virtual machine images, container layers, source trees, database snapshots, and uncompressed archives—contain substantial cross-region and cross-file block redundancy.
* **Zero-Payload Cloning:** The sender computes cryptographic SHA-256 digests for outgoing chunks on the fly. When a chunk matches any previously transmitted chunk across the transfer session, the sender suppresses the 1200-byte payload and transmits a compact **27-byte `PKT_TELEPORT` instruction**.
* **Reordering-Resilient Local Materialization:** Upon receiving `PKT_TELEPORT(TargetIdx <- SourceIdx)`, the receiver clones the payload directly from its in-memory L1 chunk cache or local storage via `pread`/`pwrite`. If `PKT_TELEPORT` arrives ahead of `SourceIdx` due to UDP reordering, the instruction is queued in a dependency map and automatically materialized the instant `SourceIdx` is committed.
* **Deadlock-Free NACK Fallback:** Any chunk requested via an explicit receiver NACK is strictly retransmitted as a raw `PKT_DATA` frame, guaranteeing 100% forward progress under arbitrary packet loss.

### 3. Zero-RTT Virtual Continuous Extent for Massive Small Files (`VirtualDirectoryExtent`)
Transferring tens of thousands of small files individually over high-RTT links suffers from catastrophic per-file handshake latency and filesystem `fsync` storms.
* **Tarless Zero-Temp-Disk Streaming:** When `-file` points to a directory, OpenFIR maps the entire directory tree (including empty subdirectories) in memory onto a **single deterministic Virtual Continuous Byte Extent** without writing any temporary archive to the sender's disk.
* **O(log N) Random-Access Retransmission:** File boundaries are indexed in an interval array. Arbitrary chunk reads and out-of-order NACK retransmissions resolve the underlying small file slices in $O(\log N)$ time via binary search.
* **Micro-File Coalescing & Cross-File Deduplication:** Multiple tiny files are automatically coalesced into single 1200-byte UDP frames, while $\phi$-Parity equations and `PKT_TELEPORT` deduplication operate seamlessly across file boundaries.

### 4. Kalman-Filtered One-Way Delay Gradient (KF-OWDG) Congestion Control
Instead of reducing transmission rates upon random packet loss or relying on two-way RTT measurements (which suffer from reverse-path ACK congestion), OpenFIR tracks the one-way arrival-versus-departure timestamp derivative:

$$\Delta d_k = (T_{\text{recv},k} - T_{\text{recv},k-1}) - (T_{\text{send},k} - T_{\text{send},k-1})$$

* **Clock-Offset Cancellation:** Constant clock offsets between sender and receiver cancel out algebraically without requiring NTP synchronization.
* **1D Kalman Noise Filtering:** A scalar Kalman filter separates OS scheduling jitter from true bottleneck queue buildup, driving a microsecond-resolution token-bucket pacer that keeps bottleneck router queues shallow while fully saturating available link capacity.

### 5. Hardened Wire Security, Stateless Cookie Handshake & Multi-Path Striping
* **Stateless HMAC Cookie Challenge (`PKT_COOKIE_CHALLENGE`):** Prevents spoofed-IP UDP reflection and unauthenticated resource allocation by requiring clients to echo a time-bound stateless HMAC-SHA256 cookie before any session or staging file is created.
* **RFC 5869 `HKDF-SHA256` & Directional `AES-256-GCM`:** Derives direction-separated 256-bit `AES-256-GCM` keys (`C2S` and `S2C`). Every datagram begins with a 19-byte outer header (`"OFIRv1" || Direction || Seq || CSPRNG-Salt32`) bound as GCM Additional Authenticated Data (`AAD`), backed by a 128-packet sliding anti-replay window.
* **Atomic Staging & Multi-Session Isolation:** All transfers stream into isolated `.openfir-part-<txid>` staging files and atomically `os.Rename` into place only after out-of-lock `fsync` and full `SHA-256` verification succeed.

---

## System Architecture

```text
+-----------------------------------------------------------------------------------+
|                                  OpenFIR SENDER                                   |
|                                                                                   |
|  [Single File OR Directory Tree] --> [Virtual Continuous Extent (O(log N) Index)] |
|                                                    |                              |
|                                                    v                              |
|                                    [SHA-256 Content-Addressable Index]            |
|                                         /                     \                   |
|                              (New Hash)/                       \(Seen Hash)       |
|                                       v                         v                 |
|  [Phi-Stride Interleaver] <----- [PKT_DATA]              [PKT_TELEPORT]           |
|             |                         \                         /                 |
|             v                          v                       v                  |
|     [PKT_PHI_PARITY] -------------> [Micro-Burst Token-Bucket Pacer]              |
|                                                |            ^                     |
|                                                v            | (Kalman OWDG)       |
|                         [HKDF + OFIRv1 Contextual AAD + AES-256-GCM Sealer]       |
|                                                |                                  |
|                                                v                                  |
|                            [Multi-Path UDP Socket Striping Pool (1..N)]           |
+------------------------------------------------|------------+---------------------+
                                                 |            |
                            Multi-5-Tuple UDP    |            | PKT_FEEDBACK
                          (High-BDP / Lossy WAN) v            | (SACK + NACK + OWDG)
+------------------------------------------------|------------+---------------------+
|                                 OpenFIR RECEIVER            |                     |
|                                                             |                     |
|                     [Multi-Core AES-256-GCM + Anti-Replay Worker Pool]            |
|                                     /          |             \                    |
|                      (PKT_PHI_PARITY)      (PKT_DATA)   (PKT_TELEPORT)            |
|                            /                   |                 \                |
|                           v                    v                  v               |
|            [Peeling Decoder Graph] ===> [Commit + L1 Cache] <=== [Teleport Queue] |
|                                                |                                  |
|                                                v                                  |
|                      [Atomic .openfir-part Staging + SHA-256 + Rename]            |
+-----------------------------------------------------------------------------------+
```

---

## Wire Frame Specification

All frames are encapsulated inside an authenticated outer AEAD envelope (35 bytes total overhead):

```text
+----------------+-----------+-------------+------------------+-------------------------+
| ASCII Hdr (6B) | Dir (1B)  |  Seq (8B)   | CSPRNG Salt (4B) | AES-256-GCM Cipher+Tag  |
|    "OFIRv1"    | 0x00/0x01 |  Monotonic  |  crypto/rand 32  | (Inner Frame + 16B Tag) |
+----------------+-----------+-------------+------------------+-------------------------+
|<--------------------- 19-Byte GCM AAD --------------------->|
                             |<---- 12-Byte AES-GCM Nonce --->|
```

Once decrypted and authenticated via `AES-256-GCM`, every inner plaintext frame begins with an 11-byte routing header (`[0x4F, 0x46, FrameType, 8B TxID]`):

| `FrameType` | Name | Inner Payload Layout (after `3B Hdr + 8B TxID`) | Description |
| :--- | :--- | :--- | :--- |
| `0x01` | `PKT_HANDSHAKE` | `[16B Cookie][8B Size][4B ChunkSz][4B Chunks][32B SHA256][1B Flags][2B NameLen][Name]` | Session initialization (`Flags=0x01` indicates directory bundle) |
| `0x02` | `PKT_HANDSHAKE_ACK` | `[4B HighestContiguous]` | Session readiness confirmation & resume offset |
| `0x03` | `PKT_DATA` | `[4B ChunkIdx][8B SendTimestampNano][2B DataLen][Payload]` | Standard data payload frame |
| `0x04` | `PKT_TELEPORT` | `[4B TargetIdx][4B SourceIdx][8B SendTimestampNano]` | Zero-byte content-addressed local clone instruction |
| `0x05` | `PKT_PHI_PARITY` | `[1B MemberCount][N*4B MemberIndices][2B ParityLen][XORPayload]` | Coprime-stride interleaved GF(2) erasure recovery frame |
| `0x06` | `PKT_FEEDBACK` | `[4B HighestContig][4B ScanLimit][4B RecvCnt][8B GradUs][8B QueueUs][2B NackCnt][N*4B Nacks]` | Selective repeat SACK/NACK bitmap + Kalman OWDG telemetry |
| `0x07` | `PKT_FIN` | *(empty)* | Sender completion notification |
| `0x08` | `PKT_FIN_ACK` | `[1B VerifiedStatus]` | End-to-end SHA-256 verification confirmation |
| `0x09` | `PKT_ERROR` | `[1B ErrorCode][2B MsgLen][ErrorMessage]` | Explicit fatal error abort notification |
| `0x0A` | `PKT_COOKIE_CHALLENGE` | `[16B StatelessHMACCookie]` | Stateless anti-spoofing handshake cookie challenge |

---

## Encrypted UDP proxy

OpenFIR also supports SOCKS5 TCP and UDP relay and fixed port forwarding through a Hysteria 2 QUIC tunnel. The Docker image includes OpenFIR and Hysteria 2 for both server and client. Native deployments require the Hysteria 2 executable on both endpoints. Run `openfir -mode proxy-init -server HOST:PORT` to generate paired profiles. [代理配置、启动与验证（中文）](docs/proxy.zh.md)

## Quick Start

### Prerequisites
* **Go 1.20+** (Zero external library dependencies; uses only the Go standard library).

### 1. Run Built-In Chaos Self-Test (`selftest` mode)
OpenFIR includes an integrated Gilbert-Elliott burst-loss chaos simulator that automatically validates **three** test suites under 8% burst packet loss:
1. A 16 MB mixed-entropy large file transfer;
2. A 200-file nested directory tree (including empty subdirectories) via Zero-RTT Virtual Extent;
3. Concurrent multi-client transfers to a single server.

```bash
go run openfir.go -mode selftest
```

### 2. Production Server & Client Usage

#### Build Binary
```bash
go build -trimpath -ldflags="-s -w" -o openfir openfir.go
```

#### Generate a 256-Bit Secret Key
```bash
export OPENFIR_SECRET=$(openssl rand -hex 32)
```

#### Start Receiver (`server` mode)
```bash
./openfir -mode server -listen 0.0.0.0:9900 -out ./downloads -secret "$OPENFIR_SECRET"
```

#### Send a Single Large File OR an Entire Directory of Small Files (`client` mode)
```bash
# Transfer a single large file
./openfir -mode client \
  -server 203.0.113.10:9900 \
  -file /path/to/large_archive.iso \
  -sockets 8 -init-mbps 100 -max-mbps 1000 \
  -secret "$OPENFIR_SECRET"

# Transfer a directory tree containing thousands of small files (Zero-RTT Virtual Extent)
./openfir -mode client \
  -server 203.0.113.10:9900 \
  -file /path/to/project_directory \
  -sockets 8 -init-mbps 100 -max-mbps 1000 \
  -secret "$OPENFIR_SECRET"
```

---

## Command-Line Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-mode` | `""` | Execution mode: `server`, `client`, or `selftest` |
| `-listen` | `0.0.0.0:9900` | UDP listen address for `server` mode |
| `-out` | `./openfir_downloads` | Output directory for received files/directories in `server` mode |
| `-server` | `127.0.0.1:9900` | Target server UDP address for `client` mode |
| `-file` | `""` | Path to the file OR directory to transmit in `client` mode |
| `-secret` | `""` | Shared secret: 64-char hex (256-bit) or `pass:<passphrase>` (or via `OPENFIR_SECRET`) |
| `-sockets` | `8` | Number of concurrent local UDP sockets for multi-path striping |
| `-init-mbps` | `50.0` | Initial pacing rate in MB/s |
| `-max-mbps` | `1000.0` | Maximum pacing rate ceiling in MB/s |
| `-overwrite` | `false` | Allow server to overwrite existing destination files |
| `-max-file-gb` | `64` | Maximum allowed transfer size in GB on server |
| `-max-sessions` | `64` | Maximum concurrent active transfer sessions on server |
| `-timeout` | `25` | Session idle/stall timeout in seconds |
| `-sim-loss` | `0.0` | Simulated packet loss ratio (`0.0` in production; `0.08` auto-applied in `selftest`) |
| `-sim-burst` | `4` | Simulated contiguous burst drop length |

---

## Cryptography & Export Control Notice

This repository utilizes standard `AES-256-GCM`, `HMAC-SHA256`, and `SHA-256` from the Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/sha256`) for packet confidentiality and authentication. This software is publicly available open-source encryption source code eligible for license exception **TSU / EAR § 742.15(b)** under the U.S. Export Administration Regulations.

---

## License

Copyright (c) 2026 The OpenFIR Authors. All rights reserved.

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
