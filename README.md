[![DOI](https://zenodo.org/badge/1460848493.svg)](https://doi.org/10.5281/zenodo.24297603)
# OpenFIR (`openfir`)

**OpenFIR** (**Open** **F**ast **I**nterleaved **R**eliable Transport Protocol) is a high-performance, multi-path, delay-gradient controlled, algebraically self-healing UDP file and directory transfer engine written in pure Go with zero external dependencies.

Engineered for high Bandwidth-Delay Product (BDP) wide-area networks, transcontinental links, satellite backhauls, and lossy wireless channels, OpenFIR decouples congestion control from random packet loss while eliminating retransmission round-trip penalties through inline coprime-stride erasure interleaving, intra-session and cross-session content-addressed zero-byte teleportation, zero-RTT virtual continuous directory extents, and self-healing $M \times N$ multi-socket 5-tuple striping.

---

## Core Architectural Innovations

### 1. Inline Staggered & Adaptive $\phi$-Parity Coprime-Stride Interleaving
Conventional Forward Error Correction (FEC) schemes group contiguous packets into block parity equations and emit parity bursts at block boundaries, which fail when network links experience Gilbert-Elliott contiguous burst losses.
* **Coprime Stride Interleaving:** OpenFIR weaves GF(2) algebraic parity equations (`PKT_PHI_PARITY`) across non-adjacent chunks separated by a coprime stride $S = 5$ within a sliding window $W = 20$. Any contiguous burst loss of up to 5 packets impacts at most **one** symbol per algebraic equation.
* **Inline Staggered Parity Injection:** Rather than emitting all 5 parity frames in a back-to-back micro-burst at the end of a 20-chunk window, parity bucket $b \in [0..4]$ is injected inline immediately after its final member chunk ($15 + b$) is sent—smoothing wire pacing and accelerating receiver peeling-decoder recovery.
* **Adaptive Cruise / Armor Scaling:** On lossless links, OpenFIR operates in **Cruise Mode** (1 parity frame per window = 5% minimal probe overhead). The instant the receiver reports a NACK or an active peeling-decoder heal event, the sender automatically shifts into **Full Armor Mode** (5 coprime-stride parity frames per window = 25% protection) and smoothly scales back once the link stabilizes.

### 2. Intra-Session & Cross-Session Content-Addressed Zero-Byte Teleportation (`PKT_TELEPORT` & `PKT_CAS_TELEPORT`)
Real-world datasets—such as virtual machine images, container layers, source trees, database snapshots, and incremental backups—contain substantial block redundancy both within a single transfer and across separate transfers over time.
* **Intra-Session Zero-Payload Cloning (`PKT_TELEPORT`):** The sender computes cryptographic SHA-256 digests for outgoing chunks on the fly. When a chunk matches any previously transmitted chunk within the current session, the sender suppresses the 1,200-byte payload and transmits a compact **27-byte `PKT_TELEPORT` instruction**.
* **Cross-Session Persistent CAS Teleportation (`PKT_CAS_TELEPORT`):** The server indexes completed files in its output directory into a persistent `GlobalCASStore` (`SHA-256 -> FilePath, Offset, Length`) and embeds an **8,192-bit (1,024-byte, $k=4$) Bloom filter summary** directly inside `PKT_HANDSHAKE_ACK` at zero extra RTT cost. When transferring an updated file or directory in a later session, matching chunks are transmitted as **55-byte `PKT_CAS_TELEPORT` instructions** carrying the full 256-bit SHA-256 digest. The receiver materializes and cryptographically verifies the chunk directly from existing local files on disk.
* **Deadlock-Free Urgent-NACK Fallback:** Any Bloom filter false positive or stale local CAS entry immediately queues an urgent NACK on the receiver, and any NACKed chunk is strictly retransmitted as a raw `PKT_DATA` frame, guaranteeing 100% forward progress and zero collision risk.

### 3. Zero-RTT Virtual Continuous Extent for Massive Small Files (`VirtualDirectoryExtent`)
Transferring tens of thousands of small files individually over high-RTT links suffers from catastrophic per-file handshake latency and filesystem `fsync` storms.
* **Tarless Zero-Temp-Disk Streaming:** When `-file` points to a directory, OpenFIR maps the entire directory tree (including empty subdirectories) in memory onto a **single deterministic Virtual Continuous Byte Extent** without writing any temporary archive to the sender's disk.
* **O(log N) Random-Access Retransmission:** File boundaries are indexed in an interval array. Arbitrary chunk reads and out-of-order NACK retransmissions resolve the underlying small file slices in $O(\log N)$ time via binary search.
* **Micro-File Coalescing & Cross-File Deduplication:** Multiple tiny files are automatically coalesced into single 1,200-byte UDP frames, while $\phi$-Parity equations and `PKT_TELEPORT` / `PKT_CAS_TELEPORT` deduplication operate seamlessly across file boundaries.

### 4. Kalman-Filtered One-Way Delay Gradient (KF-OWDG) Congestion Control
Instead of reducing transmission rates upon random packet loss or relying on two-way RTT measurements (which suffer from reverse-path ACK congestion), OpenFIR tracks the one-way arrival-versus-departure timestamp derivative:

$$\Delta d_k = (T_{\text{recv},k} - T_{\text{recv},k-1}) - (T_{\text{send},k} - T_{\text{send},k-1})$$

* **Clock-Offset Cancellation:** Constant clock offsets between sender and receiver cancel out algebraically without requiring NTP synchronization.
* **1D Kalman Noise Filtering:** A scalar Kalman filter separates OS scheduling jitter from true bottleneck queue buildup, driving a microsecond-resolution token-bucket pacer that keeps bottleneck router queues shallow while fully saturating available link capacity.

### 5. $M \times N$ Multi-Port Matrix, 600ms Dead-Path Watchdog & Polymorphic ASCII Wire Security
* **$M \times N$ Multi-Port Matrix & Strict 4-Tuple Symmetry (`-port-span` & `-sockets`):** The server binds a contiguous matrix of $M$ UDP ports (`-port-span 4` by default) with parallel kernel reader loops and advertises them in `PKT_HANDSHAKE_ACK`. All server responses are pinned strictly to the exact server socket that received each client path, ensuring 100% symmetric 4-tuple NAT traversal.
* **600ms Dead-Path Watchdog & 12 MB Byte-Quota Morphing:** Client UDP sockets bind in the low non-privileged band (`10000..32000`) and automatically hot-swap to fresh local ports and alternate server matrix ports either upon reaching a 12 MB byte quota or within **600ms** of return-path feedback silence.
* **Per-Packet Polymorphic Printable-ASCII Header (`0x21..0x7E`):** Every datagram begins with 6 per-packet polymorphic printable ASCII characters (`wire[0:6]`), where `wire[5]` embeds an `HKDF-SHA256` keyed authentication tag and directional parity bit ($47 \times 2 = 94$), followed by a key-masked sequence number (`wire[6:14]`) and a 32-bit CSPRNG salt (`wire[14:18]`). The entire 18-byte outer header is bound as `AES-256-GCM` Additional Authenticated Data (`AAD`) and protected by an 8,192-packet sliding anti-replay window.

---

## System Architecture

```text
+-----------------------------------------------------------------------------------+
|                                  OpenFIR SENDER                                   |
|                                                                                   |
|  [Single File OR Directory Tree] --> [Virtual Continuous Extent (O(log N) Index)] |
|                                                    |                              |
|                                                    v                              |
|                           [SHA-256 Content-Addressable Index + Server CAS Bloom]  |
|                                   /                |                \             |
|                        (New Hash)/      (CAS Bloom)|     (Seen Hash) \            |
|                                 v                  v                  v           |
|  [Inline Adaptive Phi-Parity] <-[PKT_DATA] [PKT_CAS_TELEPORT]   [PKT_TELEPORT]    |
|             |                      \               |                 /            |
|             v                       v              v                v             |
|     [PKT_PHI_PARITY] -------------> [Micro-Burst Token-Bucket Pacer]              |
|                                                |            ^                     |
|                                                v            | (Kalman OWDG)       |
|                   [Polymorphic ASCII AAD + MaskedSeq + AES-256-GCM Sealer]        |
|                                                |                                  |
|                                                v                                  |
|             [Self-Healing Low-Port Striping Pool (1..N, 600ms Watchdog / 12MB)]   |
+------------------------------------------------|------------+---------------------+
                                                 |            |
                               M x N 5-Tuple UDP |            | Symmetric 4-Tuple
                              (High-BDP / Lossy) v            | PKT_FEEDBACK
+------------------------------------------------|------------+---------------------+
|                                 OpenFIR RECEIVER            |                     |
|                                                             |                     |
|               [Multi-Port Server Matrix (1..M) + Multi-Core AES-GCM Pool]         |
|                           /              |              \            \            |
|            (PKT_PHI_PARITY)          (PKT_DATA)   (PKT_TELEPORT) (PKT_CAS_TELEPORT)
|                   \                      |              /            /            |
|                    v                     v             v            v             |
|            [Peeling Decoder] =====> [Commit + L1 Cache] <==== [Global CAS Store]  |
|                                                |                                  |
|                                                v                                  |
|                      [Atomic .openfir-part Staging + SHA-256 + Rename]            |
+-----------------------------------------------------------------------------------+
```

---

## Wire Frame Specification

All frames are encapsulated inside an authenticated outer AEAD envelope (34 bytes total overhead):

```text
+------------------------------+-------------------+------------------+-------------------------+
| Polymorphic ASCII Hdr (6B)   |  Masked Seq (8B)  | CSPRNG Salt (4B) | AES-256-GCM Cipher+Tag  |
| 5B [0x21..7E] + 1B KeyedTag  |  seq ^ HeaderMix  |  crypto/rand 32  | (Inner Frame + 16B Tag) |
+------------------------------+-------------------+------------------+-------------------------+
|<------------------------------- 18-Byte GCM AAD ------------------->|
                               |<-- 12-Byte Unmasked AES-GCM Nonce -->|
```

Once decrypted and authenticated via `AES-256-GCM`, every inner plaintext frame begins with an 11-byte routing header (`[0x4F, 0x46, FrameType, 8B TxID]`):

| `FrameType` | Name | Inner Payload Layout (after `3B Hdr + 8B TxID`) | Description |
| :--- | :--- | :--- | :--- |
| `0x01` | `PKT_HANDSHAKE` | `[16B Cookie][8B Size][4B ChunkSz][4B Chunks][32B SHA256][1B Flags][2B NameLen][Name]` | Session initialization (`Flags=0x01` indicates directory bundle) |
| `0x02` | `PKT_HANDSHAKE_ACK` | `[4B HighestContig][4B CASCnt][1024B CASBloom][1B PortCnt][M*2B MatrixPorts]` | Session confirmation, resume offset, CAS Bloom & Server Port Matrix |
| `0x03` | `PKT_DATA` | `[4B ChunkIdx][8B SendTimestampNano][2B DataLen][Payload]` | Standard data payload frame |
| `0x04` | `PKT_TELEPORT` | `[4B TargetIdx][4B SourceIdx][8B SendTimestampNano]` | Intra-session zero-byte content-addressed local clone instruction |
| `0x05` | `PKT_PHI_PARITY` | `[1B MemberCount][N*4B MemberIndices][2B ParityLen][XORPayload]` | Coprime-stride interleaved GF(2) erasure recovery frame |
| `0x06` | `PKT_FEEDBACK` | `[4B HighestContig][4B ScanLimit][4B RecvCnt][8B GradUs][8B QueueUs][2B Flags+NackCnt][N*4B Nacks]` | Selective repeat SACK/NACK bitmap + peeling heal signal + Kalman OWDG |
| `0x07` | `PKT_FIN` | *(empty)* | Sender completion notification |
| `0x08` | `PKT_FIN_ACK` | `[1B VerifiedStatus]` | End-to-end SHA-256 verification confirmation |
| `0x09` | `PKT_ERROR` | `[1B ErrorCode][2B MsgLen][ErrorMessage]` | Explicit fatal error abort notification |
| `0x0A` | `PKT_COOKIE_CHALLENGE` | `[16B StatelessHMACCookie]` | Stateless anti-spoofing handshake cookie challenge |
| `0x0B` | `PKT_CAS_TELEPORT` | `[4B TargetIdx][32B FullSHA256][8B SendTimestampNano]` | Cross-session persistent CAS zero-byte local clone instruction |

---

## Quick Start

### Prerequisites
* **Go 1.20+** (Zero external library dependencies; uses only the Go standard library).

### 1. Run Built-In Chaos Self-Test (`selftest` mode)
OpenFIR includes an integrated Gilbert-Elliott burst-loss chaos simulator that automatically validates **four** test suites under 8% burst packet loss (plus oversized datagram resilience):
1. Three consecutive 16 MB mixed-entropy large file transfers across a 4x8 multi-port matrix;
2. A 200-file nested directory tree (including empty subdirectories) via Zero-RTT Virtual Extent;
3. Concurrent multi-client transfers to a single server;
4. Cross-session persistent CAS instant teleportation across incremental datasets.

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
./openfir -mode server -listen 0.0.0.0:9900 -port-span 4 -out ./downloads -secret "$OPENFIR_SECRET"
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
| `-listen` | `0.0.0.0:9900` | Primary UDP listen address for `server` mode |
| `-port-span` | `4` | Number of contiguous UDP ports in server listener matrix |
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
