[![DOI](https://zenodo.org/badge/1460848493.svg)](https://doi.org/10.5281/zenodo.24297603)
# OpenFIR (`openfir`)

**OpenFIR** (**Open** **F**ast **I**nterleaved **R**eliable Transport Protocol) is a high-performance, multi-path, delay-gradient controlled, algebraically self-healing UDP file and directory transfer engine written in pure Go with zero external dependencies.

Engineered for high Bandwidth-Delay Product (BDP) wide-area networks, transcontinental links, satellite backhauls, and lossy wireless channels, OpenFIR decouples congestion control from random packet loss while eliminating retransmission round-trip penalties through inline coprime-stride erasure interleaving, intra-session and cross-session content-addressed zero-byte teleportation, zero-RTT virtual continuous directory extents, self-healing $M \times N$ multi-socket 5-tuple striping, and zero-extra-RTT X25519 Perfect Forward Secrecy (PFS).

---

## Core Architectural Innovations

### 1. Inline Staggered & Adaptive $\phi$-Parity Coprime-Stride Interleaving
Conventional Forward Error Correction (FEC) schemes group contiguous packets into block parity equations and emit parity bursts at block boundaries, which fail when network links experience Gilbert-Elliott contiguous burst losses.
* **Socket-Coprime Stride Interleaving:** OpenFIR weaves GF(2) algebraic parity equations (`PKT_PHI_PARITY`, carrying `SendTimestampNano` for continuous delay telemetry) across non-adjacent chunks separated by a stride $S$ automatically chosen to be coprime to the client socket count ($\gcd(S, N) = 1$, default $S = 5$ within sliding window $W = 4S = 20$ for $N = 8$). Any contiguous burst loss of up to $S$ packets impacts at most **one** symbol per algebraic equation, and no two members of an equation share a degraded 5-tuple path.
* **Inline Staggered Parity Injection:** Rather than emitting all $S$ parity frames in a back-to-back micro-burst at the end of a window, parity bucket $b \in [0..S-1]$ is injected inline immediately after its final member chunk ($W - S + b$) is sent—smoothing wire pacing and accelerating receiver peeling-decoder recovery.
* **Adaptive Cruise / Armor Scaling & $O(1)$ Peeling Graph:** On lossless links, OpenFIR operates in **Cruise Mode** (1 parity frame per window = 5% minimal probe overhead at $W=20$). The instant the receiver reports a NACK or an active peeling-decoder heal event, the sender automatically shifts into **Full Armor Mode** ($S$ coprime-stride parity frames per window = 25% protection) and smoothly scales back once the link stabilizes. On the receiver, an **$O(1)$ adjacency-indexed bipartite peeling graph (`chunkToEqs`, up to 2,048 active equations)** resolves cascades without linear equation scans under session locks.

### 2. Intra-Session & Cross-Session Content-Addressed Zero-Byte Teleportation (`PKT_TELEPORT` & `PKT_CAS_TELEPORT`)
Real-world datasets—such as virtual machine images, container layers, source trees, database snapshots, and incremental backups—contain substantial block redundancy both within a single transfer and across separate transfers over time.
* **Intra-Session Bidirectional Cloning (`PKT_TELEPORT`) & Sparse Zero Sentinel:** The sender computes cryptographic SHA-256 digests for outgoing chunks on the fly (with an adaptive high-entropy bypass and 1-in-64 probe for incompressible media/archives). All-zero blocks immediately emit a reserved `ZeroChunkSentinel` (`0xFFFFFFFF`) skipping both SHA-256 and source disk reads. Duplicate chunks suppress the 1,200-byte payload and transmit a compact **27-byte `PKT_TELEPORT` instruction**, modeled on the receiver as a bidirectional GF(2) equality edge (`Target ⊕ Source = 0`) that heals whichever side is missing once either arrives.
* **Cross-Session Persistent CAS Teleportation (`PKT_CAS_TELEPORT`):** The server indexes completed files in its output directory into a persistent `GlobalCASStore` (`SHA-256 -> FilePath, Offset, Length`, bounded by a 1.5s synchronous startup budget + background indexing and a 64-slot `FDLRUCache`) and embeds an **8,192-bit (1,024-byte, $k=4$) Bloom filter summary** directly inside `PKT_HANDSHAKE_ACK` at zero extra RTT cost. When transferring an updated file or directory in a later session, matching chunks are transmitted as **55-byte `PKT_CAS_TELEPORT` instructions** carrying the full 256-bit SHA-256 digest. The receiver materializes and cryptographically verifies the chunk directly from existing local files on disk.
* **Real-Time CAS Circuit Breaker & Lossless Urgent-NACK Fallback:** `PKT_FEEDBACK` continuously reports `casHits` and `casMisses`. If a fresh, unrelated dataset hits a saturated Bloom filter (hit rate $< 25\%$ after 64 probes), the client immediately trips its CAS circuit breaker to prevent false-positive storms. Any Bloom false positive or stale local CAS entry queues into a 4,096-slot lossless `urgentNacks` buffer on the receiver and strictly retransmits as a raw `PKT_DATA` frame, guaranteeing 100% forward progress and zero collision risk.

### 3. Zero-RTT Virtual Continuous Extent for Massive Small Files (`VirtualDirectoryExtent`)
Transferring tens of thousands of small files individually over high-RTT links suffers from catastrophic per-file handshake latency and filesystem `fsync` storms.
* **Tarless Zero-Temp-Disk Streaming:** When `-file` points to a directory, OpenFIR maps the entire directory tree (including empty subdirectories while skipping symlinks) in memory onto a **single deterministic Virtual Continuous Byte Extent** without writing any temporary archive to the sender's disk.
* **$O(\log N)$ Random-Access Retransmission & Bounded LRU FD Pool:** File boundaries are indexed in an interval array. Arbitrary chunk reads and out-of-order NACK retransmissions resolve the underlying small file slices in $O(\log N)$ time via binary search, backed by a bounded **64-slot `FDLRUCache`** to prevent `EMFILE` descriptor exhaustion and open/close thrashing.
* **Hardened Extraction & Micro-File Coalescing:** Multiple tiny files are automatically coalesced into single 1,200-byte UDP frames while `unpackDirectoryBundle` enforces strict root-containment validation (blocking traversal, Windows volume-relative paths, NUL/backslash injection, and symlink overwrites).

### 4. Per-Path Kalman-Filtered One-Way Delay Gradient (KF-OWDG) & CAR-Aware Congestion Control
Instead of reducing transmission rates upon random packet loss or relying on two-way RTT measurements (which suffer from reverse-path ACK congestion), OpenFIR tracks the one-way arrival-versus-departure timestamp derivative independently per active 5-tuple path:

$$\Delta d_k = (T_{\text{recv},k} - T_{\text{recv},k-1}) - (T_{\text{send},k} - T_{\text{send},k-1})$$

* **Per-Path Isolation & 10s Sliding-Window `minOWD`:** Constant clock offsets cancel out algebraically without NTP synchronization. Maintaining an independent `KalmanOWDTracker` per client 5-tuple isolates ECMP multi-path latency differentials, while a 2-bucket 10-second sliding minimum baseline eliminates quartz clock-frequency drift and standing-queue baseline creep.
* **Zero-Queue CAR Policer Defense & Windows Pacer Uncapping:** A 1D Kalman filter separates OS scheduling jitter from true bottleneck queue buildup while a **BBR-style delivery-rate ceiling (`btlBw`)** derived from receiver `RecvCount` distinguishes genuine random packet loss (no slowdown) from zero-queue carrier CAR token-bucket policers (smoothly capping pacing near `1.25×` observed delivery rate). `MicroPacer` dynamically scales burst headroom (`25ms × rateBps`, `64 KB .. 8 MB`) to sustain multi-Gbps speeds even under Windows' 15.6ms timer granularity.

### 5. $M \times N$ Multi-Port Matrix, Zero-Leak Watchdog & X25519-PFS Polymorphic Wire Security
* **$M \times N$ Multi-Port Matrix & Strict 4-Tuple Symmetry (`-port-span` & `-sockets`):** The server natively binds a contiguous matrix of $M$ UDP ports (`-port-span 4` by default) with parallel kernel reader loops and advertises them in `PKT_HANDSHAKE_ACK`. All server responses are pinned strictly to the exact server socket that received each client path, while stateless HMAC cookies bind full `(ClientIP, ClientPort, TxID, TimeSlot)` 4-tuples alongside 90-second completed-`TxID` anti-replay tombstones.
* **Zero-Leak 12 MB Morphing, Dynamic Dead-Path Watchdog & Finalization Keepalives:** Client UDP sockets bind in the low non-privileged band (`10000..32000`) and hot-swap to fresh local ports and alternate server matrix ports either upon reaching a 12 MB byte quota or after sustained unanswered-send silence (`max(600ms, 4*N*15ms + 300ms)`). Retired sockets drain and close cleanly after 2 seconds (zero FD/goroutine leaks on multi-tens-of-GB transfers), and the server emits 500ms `PKT_FEEDBACK` keepalives during `fsync`/SHA-256/unpack finalization so large transfers never trip idle watchdogs.
* **Zero-Extra-RTT X25519 PFS & AES-256 PRF Polymorphic Printable-ASCII Header:** Piggybacks ephemeral `crypto/ecdh` X25519 key agreement into handshake so every session derives unique directional `AES-256-GCM` keys (true forward secrecy and zero cross-session nonce reuse). Every datagram begins with a 22-byte authenticated outer header (`[6B Polymorphic Printable ASCII][8B MaskedSeq][4B MaskedSID][4B RandSalt]`) generated by an uninvertible **AES-256 single-block PRF** and pooled **AES-256-CTR CSPRNG**, protected by per-session server sequence counters and a **16,384-packet sliding anti-replay window**.

---

## System Architecture

```text
+-----------------------------------------------------------------------------------+
|                                  OpenFIR SENDER                                   |
|                                                                                   |
|  [Single File OR Directory Tree] --> [Virtual Continuous Extent + 64-FD LRU Pool] |
|                                                    |                              |
|                                                    v                              |
|           [Zero-Chunk Fast Path + SHA-256 Index + CAS Bloom + Circuit Breaker]    |
|                                   /                |                \             |
|                        (New Hash)/      (CAS Bloom)|     (Seen/Zero) \            |
|                                 v                  v                  v           |
|  [Coprime Adaptive Phi-Parity]<-[PKT_DATA] [PKT_CAS_TELEPORT]   [PKT_TELEPORT]    |
|             |                      \               |                 /            |
|             v                       v              v                v             |
|     [PKT_PHI_PARITY] -------------> [Adaptive-Burst CAR-Aware MicroPacer]         |
|                                                |            ^                     |
|                                                v            | (Per-Path KF-OWDG   |
|            [AES-256 PRF ASCII AAD + MaskedSeq/SID + X25519-PFS AES-256-GCM]       |
|                                                |            |  + BBR DeliveryCap) |
|                                                v            |                     |
|        [Zero-Leak Low-Port Striping Pool (1..N, Dynamic Watchdog / 12MB Morph)]   |
+------------------------------------------------|------------+---------------------+
                                                 |            |
                               M x N 5-Tuple UDP |            | Symmetric 4-Tuple
                              (High-BDP / Lossy) v            | PKT_FEEDBACK
+------------------------------------------------|------------+---------------------+
|                                 OpenFIR RECEIVER            |                     |
|                                                             |                     |
|         [Multi-Port Server Matrix (1..M) + Multi-Core X25519-PFS AES-GCM Pool]    |
|                           /              |              \            \            |
|            (PKT_PHI_PARITY)          (PKT_DATA)   (PKT_TELEPORT) (PKT_CAS_TELEPORT)
|                   \                      |              /            /            |
|                    v                     v             v            v             |
|      [O(1) Adjacency Peeling Graph] => [Commit + L1 Cache] <= [Global CAS + LRU]  |
|                                                |                                  |
|                                                v                                  |
|         [Atomic .openfir-part Staging + Finalization Keepalive + SHA-256 Rename]  |
+-----------------------------------------------------------------------------------+
```

---

## Wire Frame Specification

All frames are encapsulated inside an authenticated outer AEAD envelope (38 bytes total overhead: 22-byte AAD + 16-byte GMAC tag):

```text
+----------------------------+------------------+------------------+------------------+-------------------------+
| Polymorphic ASCII Hdr (6B) | Masked Seq (8B)  | Masked SID (4B)  | CSPRNG Salt (4B) | AES-256-GCM Cipher+Tag  |
| 5B [0x21..7E] + 1B AES-PRF | seq ^ AES-PRF    | sid ^ AES-PRF    | AES-CTR DRBG 32  | (Inner Frame + 16B Tag) |
+----------------------------+------------------+------------------+------------------+-------------------------+
|<------------------------------------- 22-Byte GCM AAD ----------------------------->|
                             |<-- 8B Nonce ---->|                  |<-- 4B Nonce --->|
```

* `SID == 0` routes pre-session handshake/challenge frames under master pre-session keys; `SID != 0` routes session frames under ephemeral per-session X25519 PFS keys.
* The 12-byte AES-256-GCM nonce is reconstructed as `UnmaskedSeq(8B) || CSPRNGSalt(4B)`.

Once decrypted and authenticated via `AES-256-GCM`, every inner plaintext frame begins with an 11-byte routing header (`[0x4F, 0x46, FrameType, 8B TxID]`):

| `FrameType` | Name | Inner Payload Layout (after `3B Hdr + 8B TxID`) | Description |
| :--- | :--- | :--- | :--- |
| `0x01` | `PKT_HANDSHAKE` | `[16B Cookie][32B ClientX25519Pub][8B Size][4B ChunkSz][4B Chunks][32B SHA256][1B Flags][2B NameLen][Name]` | Session initialization + X25519 PFS public key (`Flags=0x01` indicates directory bundle) |
| `0x02` | `PKT_HANDSHAKE_ACK` | `[4B HighestContig][4B SessionSID][32B ServerX25519Pub][4B CASCnt][1024B CASBloom][1B PortCnt][M*2B MatrixPorts]` | Session confirmation, PFS SID & server X25519 pubkey, resume offset, CAS Bloom & Server Port Matrix |
| `0x03` | `PKT_DATA` | `[4B ChunkIdx][8B SendTimestampNano][2B DataLen][Payload]` | Standard data payload frame |
| `0x04` | `PKT_TELEPORT` | `[4B TargetIdx][4B SourceIdx][8B SendTimestampNano]` | Intra-session bidirectional clone instruction (`SourceIdx=0xFFFFFFFF` denotes sparse all-zero chunk) |
| `0x05` | `PKT_PHI_PARITY` | `[8B SendTimestampNano][1B MemberCount][N*4B MemberIndices][2B ParityLen][XORPayload]` | Coprime-stride interleaved GF(2) erasure recovery frame with OWDG timestamp |
| `0x06` | `PKT_FEEDBACK` | `[4B HighestContig][4B ScanLimit][4B RecvCnt][8B GradUs][8B QueueUs][4B CASHits][4B CASMisses][2B Flags+NackCnt][N*4B Nacks]` | Selective repeat SACK/NACK bitmap + peeling/finalizing signals + CAS telemetry + Per-Path Kalman OWDG |
| `0x07` | `PKT_FIN` | *(empty)* | Sender completion notification |
| `0x08` | `PKT_FIN_ACK` | `[1B VerifiedStatus]` | End-to-end SHA-256 verification confirmation |
| `0x09` | `PKT_ERROR` | `[1B ErrorCode][2B MsgLen][ErrorMessage]` | Explicit fatal error abort notification |
| `0x0A` | `PKT_COOKIE_CHALLENGE` | `[16B StatelessHMACCookie]` | Stateless anti-spoofing 4-tuple HMAC cookie challenge |
| `0x0B` | `PKT_CAS_TELEPORT` | `[4B TargetIdx][32B FullSHA256][8B SendTimestampNano]` | Cross-session persistent CAS zero-byte local clone instruction |

---

## Quick Start

### Prerequisites
* **Go 1.20+** (Zero external library dependencies; uses only the Go standard library).

### 1. Run Built-In Chaos Self-Test (`selftest` mode)
OpenFIR includes an integrated Gilbert-Elliott burst-loss chaos simulator that automatically validates **five** test suites under 8% burst packet loss (plus oversized datagram resilience):
1. Three consecutive 16 MB mixed-entropy + sparse-zero large file transfers across a 4×8 multi-port matrix;
2. A 200-file nested directory tree (including empty subdirectories) via Zero-RTT Virtual Extent;
3. Concurrent multi-client transfers to a single server (independent X25519 PFS keys and sequence spaces);
4. Cross-session persistent CAS instant teleportation across incremental datasets;
5. Fresh high-entropy file transfer under a saturated CAS Bloom filter (validating the real-time CAS circuit breaker).

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
| `-init-mbps` | `50.0` | Initial client pacing rate in MiB/s (MegaBytes/sec; e.g., `50` ≈ 400 Mbps) |
| `-max-mbps` | `1000.0` | Maximum client pacing rate ceiling in MiB/s (MegaBytes/sec; e.g., `125` ≈ 1 Gbps) |
| `-overwrite` | `false` | Allow server to overwrite existing destination files |
| `-max-file-gb` | `64` | Maximum allowed transfer size in GB on server |
| `-max-sessions` | `64` | Maximum concurrent active transfer sessions on server |
| `-timeout` | `25` | Session idle/stall timeout in seconds |
| `-sim-loss` | `0.0` | Simulated packet loss ratio (`0.0` in production; `0.08` auto-applied in `selftest`) |
| `-sim-burst` | `4` | Simulated contiguous burst drop length |

---

## Cryptography & Export Control Notice

This repository utilizes standard `AES-256-GCM`, `AES-256` PRF/CTR, `X25519` (`crypto/ecdh`), `HMAC-SHA256`, and `SHA-256` from the Go standard library (`crypto/aes`, `crypto/cipher`, `crypto/ecdh`, `crypto/hmac`, `crypto/sha256`) for forward-secret key agreement, packet confidentiality, and authentication. This software is publicly available open-source encryption source code eligible for license exception **TSU / EAR § 742.15(b)** under the U.S. Export Administration Regulations.

---

## License

Copyright (c) 2026 The OpenFIR Authors. All rights reserved.

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
