#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
OpenFIR v2.0.0 — JSON-Driven Multi-Platform Frosted-Glass Web3 Animated Showcase Generator.
Reads canonical design tokens directly from `design/tokens.json` and renders a looping
1200x630 frosted-glass multi-platform collage (Desktop Win/macOS/Linux + Linux C11 TUI +
iOS 15+ SwiftUI + Android RenderEffect + live JSON token HUD) into `assets/openfir-v2-showcase.gif`.
"""

import json
import math
import os
import sys
from pathlib import Path
from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
TOKENS_PATH = ROOT / "design" / "tokens.json"
OUT_GIF = ROOT / "assets" / "openfir-v2-showcase.gif"

W, H = 1200, 630
NUM_FRAMES = 30
FRAME_MS = 80  # ~12.5 FPS smooth 2.4s seamless loop, fast GitHub load


def hex_rgb(s: str) -> tuple[int, int, int]:
    s = s.strip().lstrip("#")
    return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16))


def lerp_rgb(a, b, t: float):
    t = max(0.0, min(1.0, t))
    return (
        int(a[0] + (b[0] - a[0]) * t),
        int(a[1] + (b[1] - a[1]) * t),
        int(a[2] + (b[2] - a[2]) * t),
    )


def load_font(path_candidates, size: int):
    for p in path_candidates:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except Exception:
                pass
    return ImageFont.load_default()


SANS_B = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
]
SANS_R = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
]
MONO_B = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
]
MONO_R = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
]

F_TITLE = load_font(SANS_B, 18)
F_SUB   = load_font(SANS_B, 11)
F_BODY  = load_font(SANS_R, 11)
F_SMALL = load_font(SANS_B, 10)
F_TINY  = load_font(SANS_B, 9)
F_MONOB = load_font(MONO_B, 11)
F_MONO  = load_font(MONO_R, 10)
F_MONOS = load_font(MONO_R, 9)
F_KPI   = load_font(MONO_B, 14)
F_BIG   = load_font(MONO_B, 17)


def make_gradient_strip(w: int, h: int, c0, c1, alpha: int = 255, vertical: bool = False) -> Image.Image:
    im = Image.new("RGBA", (max(1, w), max(1, h)))
    dr = ImageDraw.Draw(im)
    if vertical:
        for y in range(h):
            t = y / max(1, h - 1)
            r, g, b = lerp_rgb(c0, c1, t)
            dr.line([(0, y), (w, y)], fill=(r, g, b, alpha))
    else:
        for x in range(w):
            t = x / max(1, w - 1)
            r, g, b = lerp_rgb(c0, c1, t)
            dr.line([(x, 0), (x, h)], fill=(r, g, b, alpha))
    return im


def draw_gradient_rr(base: Image.Image, box, radius: int, c0, c1, alpha: int = 255):
    x0, y0, x1, y1 = map(int, box)
    w, h = max(1, x1 - x0), max(1, y1 - y0)
    grad = make_gradient_strip(w, h, c0, c1, alpha=alpha)
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, w - 1, h - 1], radius=radius, fill=255)
    grad.putalpha(ImageChops.multiply(grad.getchannel("A"), mask))
    base.alpha_composite(grad, (x0, y0))


def draw_frosted_card(base: Image.Image, box, radius: int, tint_rgba, rim_c0, rim_c1, blur_px: int = 18, active: bool = False):
    x0, y0, x1, y1 = map(int, box)
    x0, y0 = max(0, x0), max(0, y0)
    x1, y1 = min(base.width, x1), min(base.height, y1)
    w, h = x1 - x0, y1 - y0
    if w < 6 or h < 6:
        return

    # 1. Drop shadow halo
    shadow = Image.new("RGBA", (w + 16, h + 16), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle([8, 10, w + 7, h + 9], radius=radius, fill=(0, 0, 0, 125))
    shadow = shadow.filter(ImageFilter.GaussianBlur(radius=6))
    sx, sy = max(0, x0 - 8), max(0, y0 - 8)
    base.alpha_composite(shadow.crop((0, 0, min(shadow.width, base.width - sx), min(shadow.height, base.height - sy))), (sx, sy))

    # 2. Authentic optical Gaussian-blur crop of live background
    crop = base.crop((x0, y0, x1, y1)).filter(ImageFilter.GaussianBlur(radius=blur_px))
    tint = Image.new("RGBA", (w, h), tint_rgba)
    frosted = Image.alpha_composite(crop, tint)

    # 3. Top inner frosted glass specular sheen
    sheen_h = min(44, max(12, h // 4))
    sheen = Image.new("RGBA", (w, sheen_h), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sheen)
    for y in range(sheen_h):
        a = int(28 * (1.0 - y / max(1, sheen_h - 1)) ** 1.7)
        sd.line([(0, y), (w, y)], fill=(255, 255, 255, a))
    frosted.alpha_composite(sheen, (0, 0))

    # 4. Mask to rounded rectangle & composite onto base
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, w - 1, h - 1], radius=radius, fill=255)
    frosted.putalpha(mask)
    base.alpha_composite(frosted, (x0, y0))

    # 5. Luminous Cyan->Violet gradient specular 1.5px rim
    rim_img = make_gradient_strip(w, h, rim_c0, rim_c1, alpha=215 if active else 95)
    rim_mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(rim_mask).rounded_rectangle([0, 0, w - 1, h - 1], radius=radius, outline=255, width=2 if active else 1)
    rim_img.putalpha(ImageChops.multiply(rim_img.getchannel("A"), rim_mask))
    base.alpha_composite(rim_img, (x0, y0))


def draw_hex_emblem(base: Image.Image, cx: int, cy: int, rad: float, c_cyan, c_vio):
    pts = []
    for k in range(6):
        ang = math.radians(60 * k - 30)
        pts.append((cx + rad * math.cos(ang), cy + rad * math.sin(ang)))
    glow = Image.new("RGBA", (int(rad * 4), int(rad * 4)), (0, 0, 0, 0))
    gpts = [(p[0] - cx + rad * 2, p[1] - cy + rad * 2) for p in pts]
    ImageDraw.Draw(glow).polygon(gpts, fill=(*c_cyan, 90), outline=(*c_cyan, 230))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=4))
    base.alpha_composite(glow, (int(cx - rad * 2), int(cy - rad * 2)))
    dr = ImageDraw.Draw(base)
    dr.polygon(pts, fill=(*c_vio, 70), outline=(*c_cyan, 255))
    inner = [(cx + rad * 0.45 * math.cos(math.radians(60 * k - 30)),
              cy + rad * 0.45 * math.sin(math.radians(60 * k - 30))) for k in range(6)]
    dr.polygon(inner, fill=(*c_cyan, 220))


def draw_sparkline(base: Image.Image, box, phase: float, c_cyan, c_vio, seed_off: float = 0.0):
    x0, y0, x1, y1 = map(int, box)
    w, h = x1 - x0, y1 - y0
    if w < 20 or h < 16:
        return
    overlay = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    dr = ImageDraw.Draw(overlay)

    # Subtle horizontal grid
    for g in (1, 2, 3):
        gy = int(h * g / 4)
        dr.line([(0, gy), (w, gy)], fill=(148, 163, 184, 34), width=1)

    n = 48
    pts = []
    for i in range(n):
        u = i / (n - 1)
        wave = (
            0.52
            + 0.22 * math.sin(u * 8.0 - phase * 2.0 * math.pi + seed_off)
            + 0.14 * math.sin(u * 17.0 - phase * 4.0 * math.pi + seed_off * 1.7)
            + 0.08 * math.cos(u * 5.0 + phase * 2.0 * math.pi)
        )
        wave = max(0.14, min(0.94, wave))
        px = int(u * (w - 4)) + 2
        py = int(h - 4 - wave * (h - 10))
        pts.append((px, py))

    # Translucent cyan-to-violet gradient fill under curve
    poly = [(pts[0][0], h - 2)] + pts + [(pts[-1][0], h - 2)]
    dr.polygon(poly, fill=(*c_cyan, 42))

    # Neon segmented stroke
    for i in range(n - 1):
        col = lerp_rgb(c_cyan, c_vio, i / (n - 1))
        dr.line([pts[i], pts[i + 1]], fill=(*col, 245), width=2)

    # Glowing leading point
    lx, ly = pts[-1]
    dr.ellipse([lx - 4, ly - 4, lx + 4, ly + 4], fill=(*c_cyan, 120))
    dr.ellipse([lx - 2, ly - 2, lx + 2, ly + 2], fill=(255, 255, 255, 255))
    base.alpha_composite(overlay, (x0, y0))


def render_background(phase: float, tok: dict) -> Image.Image:
    c_void = hex_rgb(tok["colors"]["bg_void"])
    c_cyan = hex_rgb(tok["colors"]["aurora_cyan"])
    c_vio  = hex_rgb(tok["colors"]["aurora_violet"])
    c_mag  = hex_rgb(tok["colors"]["aurora_magenta"])

    # Render smooth plasma at 1/4 resolution then bicubic upscale + Gaussian blur (super fast & silky!)
    sw, sh = W // 4, H // 4
    low = Image.new("RGBA", (sw, sh), (*c_void, 255))
    dr = ImageDraw.Draw(low)

    ang = phase * 2.0 * math.pi
    orbs = [
        (sw * (0.18 + 0.08 * math.sin(ang)),          sh * (0.20 + 0.08 * math.cos(ang)),          sw * 0.42, c_cyan, 130),
        (sw * (0.78 + 0.09 * math.cos(ang)),          sh * (0.76 + 0.09 * math.sin(ang)),          sw * 0.48, c_vio,  145),
        (sw * (0.58 + 0.10 * math.sin(ang + 1.3)),    sh * (0.24 + 0.09 * math.cos(ang + 0.8)),    sw * 0.34, c_mag,   90),
        (sw * (0.88 + 0.05 * math.cos(ang * 2.0)),    sh * (0.22 + 0.06 * math.sin(ang * 2.0)),    sw * 0.28, c_cyan,  95),
    ]
    for cx, cy, r, col, alpha in orbs:
        layer = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
        ImageDraw.Draw(layer).ellipse([cx - r, cy - r, cx + r, cy + r], fill=(*col, alpha))
        layer = layer.filter(ImageFilter.GaussianBlur(radius=int(r * 0.42)))
        low = Image.alpha_composite(low, layer)

    bg = low.resize((W, H), Image.Resampling.BICUBIC)

    # Futuristic Web3 perspective horizon cyber grid
    grid = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grid)
    horizon_y = 405
    # Perspective vertical rays
    for i in range(-14, 15):
        tx = W // 2 + i * 36
        bx = W // 2 + i * 118
        gd.line([(tx, horizon_y), (bx, H)], fill=(*c_cyan, 24), width=1)
    # Perspective horizontal scrolling bars
    for k in range(10):
        u = ((k + phase) / 10.0) ** 1.85
        gy = int(horizon_y + u * (H - horizon_y))
        a = int(14 + 34 * u)
        gd.line([(0, gy), (W, gy)], fill=(*c_vio, a), width=1)
    # Ambient starry coordinate dots
    for y in range(28, horizon_y, 38):
        for x in range(28, W, 38):
            gd.rectangle([x, y, x + 1, y + 1], fill=(*c_cyan, 36))
    bg = Image.alpha_composite(bg, grid)
    return bg


def draw_fiber_link(base: Image.Image, p0, ctrl, p1, phase: float, c_a, c_b):
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    dr = ImageDraw.Draw(overlay)
    pts = []
    steps = 36
    for i in range(steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * ctrl[0] + t ** 2 * p1[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * ctrl[1] + t ** 2 * p1[1]
        pts.append((x, y))
    for i in range(steps):
        col = lerp_rgb(c_a, c_b, i / steps)
        dr.line([pts[i], pts[i + 1]], fill=(*col, 72), width=2)
    # Two traveling neon data packets along the Bezier fiber
    for off in (0.0, 0.5):
        u = (phase + off) % 1.0
        px = (1 - u) ** 2 * p0[0] + 2 * (1 - u) * u * ctrl[0] + u ** 2 * p1[0]
        py = (1 - u) ** 2 * p0[1] + 2 * (1 - u) * u * ctrl[1] + u ** 2 * p1[1]
        col = lerp_rgb(c_a, c_b, u)
        dr.ellipse([px - 7, py - 7, px + 7, py + 7], fill=(*col, 95))
        dr.ellipse([px - 3, py - 3, px + 3, py + 3], fill=(255, 255, 255, 255))
    base.alpha_composite(overlay)


def render_frame(fi: int, tok: dict) -> Image.Image:
    phase = fi / NUM_FRAMES
    c_void = hex_rgb(tok["colors"]["bg_void"])
    c_cyan = hex_rgb(tok["colors"]["aurora_cyan"])
    c_vio  = hex_rgb(tok["colors"]["aurora_violet"])
    c_end  = hex_rgb(tok["colors"]["accent_primary_end"])
    c_mint = hex_rgb(tok["colors"]["accent_mint"])
    c_amb  = hex_rgb(tok["colors"]["accent_amber"])
    c_pri  = hex_rgb(tok["colors"]["text_primary"])
    c_sec  = hex_rgb(tok["colors"]["text_secondary"])
    c_mono = hex_rgb(tok["colors"]["text_mono"])

    img = render_background(phase, tok)

    # Energy fiber links connecting Desktop <-> Linux TUI <-> JSON HUD <-> iOS <-> Android
    draw_fiber_link(img, (680, 180), (705, 130), (722, 165), phase, c_cyan, c_vio)
    draw_fiber_link(img, (934, 240), (948, 210), (958, 245), (phase + 0.3) % 1.0, c_vio, c_mint)
    draw_fiber_link(img, (260, 405), (260, 418), (260, 428), (phase + 0.6) % 1.0, c_cyan, c_mint)
    draw_fiber_link(img, (620, 405), (620, 418), (620, 428), (phase + 0.15) % 1.0, c_vio, c_cyan)

    # Smooth transfer animation metrics
    pct = (28.0 + 72.0 * ((math.sin(phase * 2.0 * math.pi - 1.2) + 1.0) * 0.5))
    if fi >= NUM_FRAMES - 6:
        pct = 100.0
    merkle_ok = (pct >= 96.0)
    goodput = 685.0 + 168.0 * (0.5 + 0.5 * math.sin(phase * 2.0 * math.pi))
    plat_cycle = ["WINDOWS Direct2D", "macOS AppKit", "LINUX X11 GUI"][(fi // 12) % 3]

    # =========================================================================
    # 1. MAIN FLOATING DESKTOP FROSTED-GLASS WINDOW (Win / macOS / Linux GUI)
    # =========================================================================
    dx0, dy0, dx1, dy1 = 22, 20, 694, 406
    draw_frosted_card(img, (dx0, dy0, dx1, dy1), 20, (17, 23, 42, 166), c_cyan, c_vio, blur_px=20, active=True)
    dr = ImageDraw.Draw(img)

    # Window title strip
    draw_frosted_card(img, (dx0 + 12, dy0 + 12, dx1 - 12, dy0 + 56), 14, (26, 35, 62, 188), c_cyan, c_vio, blur_px=12, active=True)
    dr = ImageDraw.Draw(img)
    draw_hex_emblem(img, dx0 + 34, dy0 + 34, 11.5, c_cyan, c_vio)
    dr = ImageDraw.Draw(img)
    dr.text((dx0 + 52, dy0 + 23), "OPENFIR", font=F_TITLE, fill=c_pri)
    draw_gradient_rr(img, (dx0 + 144, dy0 + 23, dx0 + 206, dy0 + 44), 10, c_cyan, c_end, alpha=230)
    dr = ImageDraw.Draw(img)
    dr.text((dx0 + 153, dy0 + 27), "v2.0.0", font=F_SUB, fill=c_void)

    # Tabs (from design/tokens.json)
    tx = dx0 + 220
    for idx, tinfo in enumerate(tok["tabs"]):
        act = (idx == 0)
        if act:
            draw_gradient_rr(img, (tx, dy0 + 22, tx + 62, dy0 + 45), 11, c_cyan, c_end, alpha=240)
        else:
            dr.rounded_rectangle([tx, dy0 + 22, tx + 62, dy0 + 45], radius=11, fill=(10, 15, 29, 170))
        dr = ImageDraw.Draw(img)
        dr.text((tx + 12, dy0 + 27), tinfo["label"], font=F_SMALL, fill=c_void if act else c_sec)
        tx += 68

    # Live desktop platform cycling badge
    dr.rounded_rectangle([dx1 - 166, dy0 + 22, dx1 - 22, dy0 + 45], radius=11, fill=(10, 15, 29, 210), outline=(*c_mint, 160))
    dr.text((dx1 - 156, dy0 + 28), f"● {plat_cycle}", font=F_TINY, fill=c_mint)

    # Left Control Glass Pane
    lc = (dx0 + 14, dy0 + 68, dx0 + 318, dy1 - 14)
    draw_frosted_card(img, lc, 16, (15, 22, 40, 155), (180, 235, 255), c_vio, blur_px=14, active=False)
    dr = ImageDraw.Draw(img)
    dr.text((lc[0] + 14, lc[1] + 12), "PUSH · HYBRID TLS 1.3 + UDP GSO", font=F_SMALL, fill=c_cyan)

    fields = [
        ("SERVER ENDPOINT", "files.openfir.io:443"),
        ("256-BIT SECRET (X25519 PFS)", "9f4c82d1a0b3...7e8a1f"),
        ("PAYLOAD (VIRTUAL EXTENT)", "ai-weights-2026/ · 12.4 GiB"),
    ]
    fy = lc[1] + 34
    for lbl, val in fields:
        dr.text((lc[0] + 14, fy), lbl, font=F_TINY, fill=c_sec)
        dr.rounded_rectangle([lc[0] + 14, fy + 13, lc[2] - 14, fy + 38], radius=8, fill=(10, 15, 29, 200), outline=(255, 255, 255, 42))
        dr.text((lc[0] + 22, fy + 20), val, font=F_MONO, fill=c_mono)
        fy += 48

    # Transport Pills
    dr.text((lc[0] + 14, fy), "DATA PLANE", font=F_TINY, fill=c_sec)
    modes = [("AUTO HYBRID", True), ("UDP GSO", False), ("TLS 1.3", False)]
    mx = lc[0] + 14
    for m_lbl, m_act in modes:
        mw = 88
        if m_act:
            draw_gradient_rr(img, (mx, fy + 14, mx + mw, fy + 38), 8, c_cyan, c_end, alpha=235)
        else:
            dr.rounded_rectangle([mx, fy + 14, mx + mw, fy + 38], radius=8, fill=(10, 15, 29, 180))
        dr = ImageDraw.Draw(img)
        dr.text((mx + 10, fy + 21), m_lbl, font=F_TINY, fill=c_void if m_act else c_sec)
        mx += mw + 6

    # Primary CTA Glow Button
    cta = (lc[0] + 14, lc[3] - 44, lc[2] - 14, lc[3] - 12)
    draw_gradient_rr(img, cta, 10, c_mint if merkle_ok else c_cyan, c_cyan if merkle_ok else c_end, alpha=245)
    dr = ImageDraw.Draw(img)
    dr.text((cta[0] + 42, cta[1] + 10),
            "✓ MERKLE 100% VERIFIED" if merkle_ok else "⚡ HYBRID STREAM ACTIVE",
            font=F_SUB, fill=c_void)

    # Right Live Telemetry Glass Pane
    rc = (dx0 + 330, dy0 + 68, dx1 - 14, dy1 - 14)
    draw_frosted_card(img, rc, 16, (15, 22, 40, 155), (180, 235, 255), c_vio, blur_px=14, active=False)
    dr = ImageDraw.Draw(img)
    dr.text((rc[0] + 14, rc[1] + 12), "LIVE TELEMETRY · ZERO-COPY ENGINE", font=F_SMALL, fill=c_vio)
    dr.text((rc[0] + 14, rc[1] + 30), f"{pct:5.1f}%  ·  {12.4 * pct / 100.0:4.1f} / 12.4 GiB", font=F_MONOB, fill=c_pri)
    dr.text((rc[2] - 88, rc[1] + 30), "HYBRID GSO", font=F_SMALL, fill=c_cyan)

    # Neon Progress Bar + Leading Glow Orb
    pb = (rc[0] + 14, rc[1] + 49, rc[2] - 14, rc[1] + 61)
    dr.rounded_rectangle(pb, radius=6, fill=(10, 15, 29, 220))
    fill_x = int(pb[0] + (pb[2] - pb[0]) * (pct / 100.0))
    if fill_x > pb[0] + 6:
        draw_gradient_rr(img, (pb[0], pb[1], fill_x, pb[3]), 6, c_cyan, c_end, alpha=250)
        dr = ImageDraw.Draw(img)
        dr.ellipse([fill_x - 5, pb[1] - 2, fill_x + 5, pb[3] + 2], fill=(255, 255, 255, 240))

    # 2x2 Frosted KPI Micro-Tiles
    kw = (rc[2] - rc[0] - 36) // 2
    kpis = [
        (rc[0] + 14,          rc[1] + 72, "GOODPUT",        f"{goodput:5.1f} MiB/s", c_cyan),
        (rc[0] + 22 + kw,     rc[1] + 72, "HYBRID WIRE",    "UDP 94% · TLS 6%",      c_mono),
        (rc[0] + 14,          rc[1] + 128,"RABIN CDC CAS",  "98.4% DEDUP HIT",       c_mint),
        (rc[0] + 22 + kw,     rc[1] + 128,"GF(256) RS FEC", "0% OVERHEAD · 1.2ms",   c_amb),
    ]
    for kx, ky, kl, kv, kc in kpis:
        draw_frosted_card(img, (kx, ky, kx + kw, ky + 48), 10, (26, 35, 62, 185), c_cyan, c_vio, blur_px=8, active=False)
        dr = ImageDraw.Draw(img)
        dr.text((kx + 10, ky + 7), kl, font=F_TINY, fill=c_sec)
        dr.text((kx + 10, ky + 23), kv, font=F_MONOB, fill=kc)

    # Live Neon Throughput Sparkline Card
    sp_box = (rc[0] + 14, rc[1] + 186, rc[2] - 14, rc[3] - 44)
    draw_frosted_card(img, sp_box, 10, (20, 29, 52, 185), c_cyan, c_vio, blur_px=8, active=False)
    dr = ImageDraw.Draw(img)
    dr.text((sp_box[0] + 10, sp_box[1] + 6), "REAL-TIME THROUGHPUT SPARKLINE (MiB/s)", font=F_TINY, fill=c_sec)
    draw_sparkline(img, (sp_box[0] + 8, sp_box[1] + 20, sp_box[2] - 8, sp_box[3] - 6), phase, c_cyan, c_vio)

    # Merkle Proof Bar
    mk_box = (rc[0] + 14, rc[3] - 36, rc[2] - 14, rc[3] - 10)
    dr = ImageDraw.Draw(img)
    dr.rounded_rectangle(mk_box, radius=8, fill=(10, 15, 29, 220), outline=(*c_mint, 140 if merkle_ok else 40))
    dr.text((mk_box[0] + 10, mk_box[1] + 7),
            "✓ MERKLE BLAKE2b: 7b4e91c0a3f8...e219 [VERIFIED]" if merkle_ok else "◈ STREAMING MERKLE TREE · X25519 PFS AES-256-GCM",
            font=F_MONOS, fill=c_mint if merkle_ok else c_mono)

    # =========================================================================
    # 2. BOTTOM-LEFT: LINUX CLI FROSTED-GLASS TUI (Pure C11 · 72 KiB · 0 ncurses)
    # =========================================================================
    tb = (22, 422, 466, 578)
    draw_frosted_card(img, tb, 16, (9, 14, 28, 195), c_cyan, c_mint, blur_px=16, active=True)
    dr = ImageDraw.Draw(img)
    dr.text((tb[0] + 14, tb[1] + 10), "╭─ ◆ OPENFIR v2.0 LINUX CLI TUI · PURE C11 ─────────────╮", font=F_MONO, fill=c_cyan)
    dr.text((tb[0] + 14, tb[1] + 28), "│  [1 PUSH]  [2 PULL]  [3 SERVER]  [4 AUDIT]   72 KiB   │", font=F_MONO, fill=c_pri)
    dr.text((tb[0] + 14, tb[1] + 45), "│  24-bit TrueColor Spatial Blur · ZERO ncurses         │", font=F_MONO, fill=c_sec)

    # Animated pseudo-Braille / block terminal sparkline bars inside TUI
    bars_x = tb[0] + 24
    bars_y = tb[1] + 114
    for b in range(28):
        bh = int(10 + 36 * (0.5 + 0.5 * math.sin(b * 0.42 - phase * 2.0 * math.pi)))
        col = lerp_rgb(c_cyan, c_vio, b / 27.0)
        dr.rectangle([bars_x + b * 10, bars_y - bh, bars_x + b * 10 + 6, bars_y], fill=(*col, 235))
    dr.text((tb[0] + 318, tb[1] + 72), f"{goodput:5.1f} MiB/s", font=F_MONOB, fill=c_mint)
    dr.text((tb[0] + 318, tb[1] + 90), "UDP_SEGMENT", font=F_MONOS, fill=c_cyan)
    dr.text((tb[0] + 318, tb[1] + 104), "RS GF(256)", font=F_MONOS, fill=c_vio)
    filled_blocks = max(1, min(20, int(pct / 5.0 + 0.5)))
    bar_str = ("█" * filled_blocks) + ("░" * (20 - filled_blocks))
    dr.text((tb[0] + 14, tb[1] + 123), f"│  {bar_str}  {pct:5.1f}%  ✓ MERKLE OK       │", font=F_MONO, fill=c_mint)
    dr.text((tb[0] + 14, tb[1] + 139), "╰───────────────────────────────────────────────────────╯", font=F_MONO, fill=c_vio)

    # =========================================================================
    # 3. BOTTOM-CENTER: LIVE JSON DESIGN TOKENS HUD (`design/tokens.json`)
    # =========================================================================
    jb = (480, 422, 704, 578)
    draw_frosted_card(img, jb, 16, (10, 15, 30, 195), c_vio, c_cyan, blur_px=16, active=False)
    dr = ImageDraw.Draw(img)
    dr.text((jb[0] + 12, jb[1] + 10), "{ design/tokens.json }", font=F_MONOB, fill=c_vio)
    json_lines = [
        ('"version":',  '"2.0.0"',    c_mint),
        ('"bg_void":',  '"#070913"',  c_mono),
        ('"cyan":',     '"#00F0FF"',  c_cyan),
        ('"violet":',   '"#8B5CF6"',  c_vio),
        ('"blur_px":',  '24',         c_amb),
        ('"ui_deps":',  '0',          c_mint),
        ('"license":',  '"Apache-2"', c_pri),
    ]
    jy = jb[1] + 32
    for k_txt, v_txt, v_col in json_lines:
        dr.text((jb[0] + 14, jy), k_txt, font=F_MONOS, fill=c_sec)
        dr.text((jb[0] + 96, jy), v_txt, font=F_MONOS, fill=v_col)
        jy += 17
    # Animated glowing horizontal JSON scan laser (alpha-composited)
    scan_ov = Image.new("RGBA", (jb[2] - jb[0], jb[3] - jb[1]), (0, 0, 0, 0))
    scan_y = int(28 + (jb[3] - jb[1] - 38) * ((math.sin(phase * 2.0 * math.pi) + 1.0) * 0.5))
    ImageDraw.Draw(scan_ov).line([(8, scan_y), (jb[2] - jb[0] - 8, scan_y)], fill=(*c_cyan, 145), width=2)
    img.alpha_composite(scan_ov, (jb[0], jb[1]))

    # =========================================================================
    # 4. RIGHT: iOS 15–26+ GLASS SMARTPHONE (Pure Swift · .ultraThinMaterial)
    # =========================================================================
    ib = (720, 26, 944, 488)
    draw_frosted_card(img, ib, 32, (16, 22, 42, 178), c_cyan, c_vio, blur_px=22, active=True)
    dr = ImageDraw.Draw(img)
    # Dynamic Island
    dr.rounded_rectangle([ib[0] + 74, ib[1] + 11, ib[2] - 74, ib[1] + 25], radius=7, fill=(4, 6, 12, 245))
    dr.text((ib[0] + 18, ib[1] + 38), "◆ OPENFIR", font=F_SUB, fill=c_pri)
    dr.text((ib[2] - 76, ib[1] + 38), "iOS 15+", font=F_SMALL, fill=c_cyan)

    # Segmented tabs
    draw_gradient_rr(img, (ib[0] + 16, ib[1] + 60, ib[0] + 108, ib[1] + 82), 10, c_cyan, c_end, alpha=235)
    dr = ImageDraw.Draw(img)
    dr.rounded_rectangle([ib[0] + 114, ib[1] + 60, ib[2] - 16, ib[1] + 82], radius=10, fill=(10, 15, 29, 180))
    dr.text((ib[0] + 44, ib[1] + 65), "PUSH", font=F_SMALL, fill=c_void)
    dr.text((ib[0] + 144, ib[1] + 65), "PULL", font=F_SMALL, fill=c_sec)

    # Circular Neon Progress Gauge inside ultraThinMaterial card (true alpha-blended glass track!)
    draw_frosted_card(img, (ib[0] + 16, ib[1] + 92, ib[2] - 16, ib[1] + 242), 16, (26, 35, 62, 180), c_cyan, c_vio, blur_px=10, active=False)
    ring_ov = Image.new("RGBA", (140, 140), (0, 0, 0, 0))
    rdr = ImageDraw.Draw(ring_ov)
    gr = 52
    rdr.arc([70 - gr, 70 - gr, 70 + gr, 70 + gr], 0, 360, fill=(255, 255, 255, 36), width=8)
    rdr.arc([70 - gr, 70 - gr, 70 + gr, 70 + gr], -90, -90 + int(360 * pct / 100.0), fill=(*c_cyan, 250), width=8)
    gcx, gcy = (ib[0] + ib[2]) // 2, ib[1] + 166
    img.alpha_composite(ring_ov, (gcx - 70, gcy - 70))
    dr = ImageDraw.Draw(img)
    dr.text((gcx - 26, gcy - 13), f"{pct:4.0f}%", font=F_BIG, fill=c_pri)
    dr.text((gcx - 36, gcy + 10), f"{goodput:4.0f} MiB/s", font=F_MONOS, fill=c_mint)

    # Mini Sparkline + Telemetry
    draw_frosted_card(img, (ib[0] + 16, ib[1] + 252, ib[2] - 16, ib[1] + 356), 14, (20, 29, 52, 185), c_cyan, c_vio, blur_px=8, active=False)
    dr = ImageDraw.Draw(img)
    dr.text((ib[0] + 26, ib[1] + 260), "SWIFTUI · .ultraThinMaterial", font=F_TINY, fill=c_sec)
    draw_sparkline(img, (ib[0] + 24, ib[1] + 276, ib[2] - 24, ib[1] + 348), phase, c_cyan, c_vio, seed_off=1.4)

    # Bottom iOS CTA & Badge
    draw_gradient_rr(img, (ib[0] + 16, ib[1] + 370, ib[2] - 16, ib[1] + 404), 11, c_cyan, c_end, alpha=240)
    dr = ImageDraw.Draw(img)
    dr.text((ib[0] + 46, ib[1] + 381), "✓ MERKLE VERIFIED" if merkle_ok else "⚡ TRANSFERRING", font=F_SMALL, fill=c_void)
    dr.text((ib[0] + 30, ib[1] + 420), "Pure Swift · 2.3 MiB IPA", font=F_MONOS, fill=c_mono)
    dr.text((ib[0] + 40, ib[1] + 436), "ZERO CocoaPods / SPM", font=F_MONOS, fill=c_sec)

    # =========================================================================
    # 5. FAR-RIGHT: ANDROID 8–15+ GLASS PHONE (Pure Kotlin · RenderEffect)
    # =========================================================================
    ab = (958, 66, 1178, 526)
    draw_frosted_card(img, ab, 28, (16, 22, 42, 178), c_vio, c_mint, blur_px=22, active=True)
    dr = ImageDraw.Draw(img)
    # Punch-hole camera
    dr.ellipse([(ab[0] + ab[2]) // 2 - 5, ab[1] + 12, (ab[0] + ab[2]) // 2 + 5, ab[1] + 22], fill=(4, 6, 12, 245))
    dr.text((ab[0] + 16, ab[1] + 34), "◆ OPENFIR", font=F_SUB, fill=c_pri)
    dr.text((ab[2] - 78, ab[1] + 34), "ANDROID", font=F_SMALL, fill=c_mint)

    # Android Frosted Telemetry Card
    draw_frosted_card(img, (ab[0] + 14, ab[1] + 58, ab[2] - 14, ab[1] + 226), 16, (24, 33, 58, 185), c_vio, c_cyan, blur_px=10, active=False)
    dr = ImageDraw.Draw(img)
    dr.text((ab[0] + 24, ab[1] + 68), "RenderEffect GPU BLUR", font=F_TINY, fill=c_cyan)
    dr.text((ab[0] + 24, ab[1] + 86), f"{goodput * 0.96:5.1f} MiB/s", font=F_BIG, fill=c_pri)
    dr.text((ab[0] + 24, ab[1] + 110), "Lane: HYBRID UDP+TLS1.3", font=F_MONOS, fill=c_mono)
    dr.text((ab[0] + 24, ab[1] + 126), "CDC CAS: 98.4%  RS: 0%", font=F_MONOS, fill=c_mint)
    # Progress Bar
    apb = (ab[0] + 24, ab[1] + 148, ab[2] - 24, ab[1] + 158)
    dr.rounded_rectangle(apb, radius=5, fill=(10, 15, 29, 220))
    afill = int(apb[0] + (apb[2] - apb[0]) * (pct / 100.0))
    if afill > apb[0] + 4:
        draw_gradient_rr(img, (apb[0], apb[1], afill, apb[3]), 5, c_mint, c_cyan, alpha=245)
    dr = ImageDraw.Draw(img)
    dr.text((ab[0] + 24, ab[1] + 168), f"{pct:5.1f}% · DT_SONAME OK", font=F_MONOS, fill=c_sec)
    dr.text((ab[0] + 24, ab[1] + 186), "arm64-v8a + x86_64 NDK", font=F_MONOS, fill=c_sec)
    dr.text((ab[0] + 24, ab[1] + 202), "C11 JNI Zero-Copy Core", font=F_MONOS, fill=c_vio)

    # Mini Sparkline
    draw_frosted_card(img, (ab[0] + 14, ab[1] + 236, ab[2] - 14, ab[1] + 344), 14, (20, 29, 52, 185), c_vio, c_mint, blur_px=8, active=False)
    dr = ImageDraw.Draw(img)
    dr.text((ab[0] + 24, ab[1] + 244), "LIVE GOODPUT SPARKLINE", font=F_TINY, fill=c_sec)
    draw_sparkline(img, (ab[0] + 22, ab[1] + 260, ab[2] - 22, ab[1] + 336), phase, c_mint, c_cyan, seed_off=2.6)

    # Bottom Android CTA & Badge
    draw_gradient_rr(img, (ab[0] + 14, ab[1] + 358, ab[2] - 14, ab[1] + 392), 11, c_mint, c_cyan, alpha=240)
    dr = ImageDraw.Draw(img)
    dr.text((ab[0] + 40, ab[1] + 369), "✓ MERKLE VERIFIED" if merkle_ok else "⚡ HYBRID ACTIVE", font=F_SMALL, fill=c_void)
    dr.text((ab[0] + 24, ab[1] + 408), "Pure Kotlin · 5.5 MiB APK", font=F_MONOS, fill=c_mono)
    dr.text((ab[0] + 26, ab[1] + 424), "ZERO AndroidX / Compose", font=F_MONOS, fill=c_sec)

    # =========================================================================
    # 6. BOTTOM UNIFIED PLATFORM SHOWCASE DOCK BAR (Centered)
    # =========================================================================
    dock = (22, 588, 1178, 620)
    draw_frosted_card(img, dock, 15, (14, 20, 38, 210), c_cyan, c_vio, blur_px=12, active=True)
    dr = ImageDraw.Draw(img)
    pills = [
        ("WINDOWS C++20 Direct2D", c_cyan),
        ("macOS Swift AppKit",     c_vio),
        ("iOS 15+ SwiftUI",        c_cyan),
        ("ANDROID Kotlin+NDK",     c_mint),
        ("LINUX C++20 X11",        c_vio),
        ("LINUX C11 TUI",          c_mint),
        ("0 THIRD-PARTY UI DEPS · APACHE-2.0", c_amb),
    ]
    gap = 26
    total_w = sum(int(dr.textlength(f"◆ {ptxt}", font=F_TINY)) for ptxt, _ in pills) + gap * (len(pills) - 1)
    px = dock[0] + max(16, (dock[2] - dock[0] - total_w) // 2)
    for ptxt, pcol in pills:
        dr.text((px, dock[1] + 10), f"◆ {ptxt}", font=F_TINY, fill=pcol)
        px += int(dr.textlength(f"◆ {ptxt}", font=F_TINY)) + gap

    return img.convert("RGB")


def main():
    with open(TOKENS_PATH, "r", encoding="utf-8") as f:
        tok = json.load(f)

    OUT_GIF.parent.mkdir(parents=True, exist_ok=True)
    frames = []
    for i in range(NUM_FRAMES):
        fr = render_frame(i, tok)
        if i == 0:
            fr.save("/tmp/openfir_preview_f00.png")
        elif i == NUM_FRAMES - 1:
            fr.save("/tmp/openfir_preview_last.png")
        # High-quality adaptive 256-color palette per frame for crisp gradients & frosted glass
        frames.append(fr.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.FLOYDSTEINBERG))

    frames[0].save(
        OUT_GIF,
        save_all=True,
        append_images=frames[1:],
        duration=FRAME_MS,
        loop=0,
        optimize=True,
        disposal=2,
    )
    sz_kb = OUT_GIF.stat().st_size / 1024.0
    print(f"[Showcase] Rendered {NUM_FRAMES} frames ({W}x{H}) -> {OUT_GIF} ({sz_kb:.1f} KiB)")


if __name__ == "__main__":
    main()
