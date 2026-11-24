<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenFIR Unified Design System — *Obsidian Frost × Neon Aurora*

Every native OpenFIR client (Linux CLI TUI, Linux Desktop X11 GUI, Windows Direct2D/DWM Acrylic, macOS AppKit Vibrancy, iOS SwiftUI UltraThinMaterial, and Android RenderEffect/Canvas) implements the exact same modern Web3 glassmorphism visual identity from scratch with **zero third-party UI dependencies**.

## 1. Visual Architecture
- **Obsidian Void Canvas (`#070913`)**: Deep cosmic obsidian canvas energized by three slowly orbiting radial plasma orbs (`#00F0FF` Cyan, `#8B5CF6` Violet, `#EC4899` Magenta) rendered on GPU/SIMD/24-bit TrueColor surfaces.
- **Multi-Layer Frosted Glass**:
  - **Windows**: Native Windows 11 DWM Acrylic (`DWMWA_SYSTEMBACKDROP_TYPE = DWMSBT_TRANSIENTWINDOW`) + GPU Direct2D translucent glass panels with 1px specular neon-gradient rims.
  - **macOS**: Native `NSVisualEffectView` (`.hudWindow` / `.underWindowBackground`) layered over animated `CAGradientLayer` aurora plasma.
  - **iOS**: Native SwiftUI `.ultraThinMaterial` cards over an animated `Canvas` plasma backdrop with neon hairline strokes.
  - **Android**: Native Android 12+ GPU `RenderEffect.createBlurEffect` frosted glass (with translucent obsidian glass fallback on Android 8–11) over custom hardware-accelerated `Canvas` aurora.
  - **Linux Desktop GUI**: Custom C++20 separable multi-pass Gaussian blur compositor over raw X11 ARGB32 double-buffered framebuffers.
  - **Linux CLI TUI**: Pure C11 24-bit TrueColor double-buffered terminal compositor blending live animated Unicode half-block (`▀`) aurora plasma through `rgba(17, 23, 42, 0.68)` frosted glass cards with crisp rounded box-drawing borders (`╭─╮│╰─╯`) and 2×4 sub-pixel Braille (`⠀..⣿`) sparklines.

## 2. Unified 4-Mode Navigation & Telemetry Contract
All 6 clients share identical functional structure and real-time `openfir_core` C ABI telemetry:
1. **Header Strip**: Glowing hexagonal `OPENFIR` emblem, `v1.1` pill, live engine status LED (`IDLE` / `ACTIVE` / `MERKLE VERIFIED` / `SERVER LIVE`), and 4 frosted glass tabs (`PUSH`, `PULL`, `SERVER`, `AUDIT`).
2. **Control Glass Card**: Endpoint, 256-bit Secret + 1-click `KEYGEN`, native File/Directory picker, Transport Mode segmented pills (`AUTO` / `UDP` / `TCP`), Streams, Max MiB/s, Overwrite toggle, and primary Cyan-to-Violet gradient CTA.
3. **Telemetry Glass Card**: Neon gradient progress bar, 60-sample live MiB/s sparkline area graph, 4 frosted KPI tiles (`GOODPUT`, `HYBRID LANE`, `CDC CAS / DEDUP`, `GF(256) RS FEC`), and cryptographic `SHA-256 MERKLE ROOT` verification strip.
