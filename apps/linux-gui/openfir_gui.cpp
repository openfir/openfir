// SPDX-License-Identifier: Apache-2.0
//
// OpenFIR Linux Desktop Native Frosted-Glass GUI (openfir-gui)
// Pure C++20 + Raw X11 (libX11) + Xft — ZERO GTK, ZERO Qt, ZERO Cairo, ZERO Skia,
// ZERO Electron, ZERO third-party dependencies.
// Features a custom 100% from-scratch ARGB32 separable Gaussian-blur glassmorphism
// compositor, SDF anti-aliased neon-gradient geometry, live animated Web3 aurora
// plasma, 60-sample anti-aliased throughput sparkline, and in-window POSIX file browser.

#include <X11/Xatom.h>
#include <X11/Xft/Xft.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "openfir.h"

namespace {

struct Color {
    uint8_t r, g, b, a;
};

constexpr Color COL_VOID         {  7,   9,  19, 255};
constexpr Color COL_CYAN         {  0, 240, 255, 255};
constexpr Color COL_VIOLET       {139,  92, 246, 255};
constexpr Color COL_ACCENT_END   {124,  58, 237, 255};
constexpr Color COL_MAGENTA      {236,  72, 153, 255};
constexpr Color COL_GLASS_SURF   { 17,  23,  42, 160};
constexpr Color COL_GLASS_ELEV   { 26,  35,  62, 194};
constexpr Color COL_GLASS_INPUT  { 10,  15,  29, 195};
constexpr Color COL_MINT         { 16, 249, 160, 255};
constexpr Color COL_AMBER        {255, 176,  32, 255};
constexpr Color COL_ROSE         {255,  77, 141, 255};
constexpr Color COL_TEXT_PRI     {248, 250, 252, 255};
constexpr Color COL_TEXT_SEC     {148, 163, 184, 255};
constexpr Color COL_TEXT_MUTED   {100, 116, 139, 255};
constexpr Color COL_TEXT_MONO    {125, 211, 252, 255};

inline uint8_t clamp_u8(float v) {
    if (v <= 0.0f) return 0;
    if (v >= 255.0f) return 255;
    return static_cast<uint8_t>(v + 0.5f);
}

inline uint32_t pack_bgra(uint8_t r, uint8_t g, uint8_t b) {
    return (0xFFu << 24) | (static_cast<uint32_t>(r) << 16) |
           (static_cast<uint32_t>(g) << 8) | static_cast<uint32_t>(b);
}

inline Color lerp_col(Color a, Color b, float t) {
    t = std::clamp(t, 0.0f, 1.0f);
    return {
        clamp_u8(a.r + (b.r - a.r) * t),
        clamp_u8(a.g + (b.g - a.g) * t),
        clamp_u8(a.b + (b.b - a.b) * t),
        clamp_u8(a.a + (b.a - a.a) * t)
    };
}

inline void blend_pixel(uint32_t &dst, Color src, float alpha) {
    if (alpha <= 0.001f) return;
    uint8_t dr = static_cast<uint8_t>((dst >> 16) & 0xFF);
    uint8_t dg = static_cast<uint8_t>((dst >> 8) & 0xFF);
    uint8_t db = static_cast<uint8_t>(dst & 0xFF);
    float inv = 1.0f - alpha;
    uint8_t r = clamp_u8(src.r * alpha + dr * inv);
    uint8_t g = clamp_u8(src.g * alpha + dg * inv);
    uint8_t b = clamp_u8(src.b * alpha + db * inv);
    dst = pack_bgra(r, g, b);
}

inline float sd_rounded_box(float px, float py, float cx, float cy, float hw, float hh, float r) {
    float qx = std::fabs(px - cx) - (hw - r);
    float qy = std::fabs(py - cy) - (hh - r);
    float ox = std::max(qx, 0.0f);
    float oy = std::max(qy, 0.0f);
    return std::sqrt(ox * ox + oy * oy) + std::min(std::max(qx, qy), 0.0f) - r;
}

struct Rect {
    int x = 0, y = 0, w = 0, h = 0;
    bool contains(int px, int py) const {
        return px >= x && px < x + w && py >= y && py < y + h;
    }
};

// ============================================================================
// Pure C++20 ARGB32 Separable Gaussian-Blur Glassmorphism Compositor
// ============================================================================
class GlassSurface {
public:
    int w = 0, h = 0;
    std::vector<uint32_t> pixels;
    std::vector<uint32_t> scratch;
    std::vector<uint32_t> blur_tmp;

    void resize(int nw, int nh) {
        if (nw == w && nh == h && !pixels.empty()) return;
        w = std::max(nw, 320);
        h = std::max(nh, 240);
        pixels.assign(static_cast<size_t>(w) * static_cast<size_t>(h), pack_bgra(7, 9, 19));
        scratch.resize(pixels.size());
        blur_tmp.resize(pixels.size());
    }

    // Animated Obsidian Frost x Neon Aurora Web3 plasma + subtle grid backdrop
    void draw_aurora_backdrop(float t) {
        const float cx1 = w * (0.20f + 0.06f * std::sin(t * 0.45f));
        const float cy1 = h * (0.22f + 0.06f * std::cos(t * 0.37f));
        const float cx2 = w * (0.80f + 0.07f * std::cos(t * 0.32f));
        const float cy2 = h * (0.78f + 0.06f * std::sin(t * 0.41f));
        const float cx3 = w * (0.58f + 0.08f * std::sin(t * 0.27f + 1.3f));
        const float cy3 = h * (0.26f + 0.07f * std::cos(t * 0.30f + 0.7f));
        const float inv_r1 = 1.0f / (static_cast<float>(w) * static_cast<float>(w) * 0.16f);
        const float inv_r2 = 1.0f / (static_cast<float>(w) * static_cast<float>(w) * 0.19f);
        const float inv_r3 = 1.0f / (static_cast<float>(w) * static_cast<float>(w) * 0.13f);

        for (int y = 0; y < h; ++y) {
            uint32_t *row = pixels.data() + static_cast<size_t>(y) * w;
            float dy1 = y - cy1, dy2 = y - cy2, dy3 = y - cy3;
            bool gy = (y % 32 == 0);
            for (int x = 0; x < w; ++x) {
                float dx1 = x - cx1, dx2 = x - cx2, dx3 = x - cx3;
                float g1 = std::exp(-(dx1 * dx1 + dy1 * dy1) * inv_r1) * 0.34f;
                float g2 = std::exp(-(dx2 * dx2 + dy2 * dy2) * inv_r2) * 0.36f;
                float g3 = std::exp(-(dx3 * dx3 + dy3 * dy3) * inv_r3) * 0.17f;

                float r = COL_VOID.r + COL_CYAN.r * g1 + COL_VIOLET.r * g2 + COL_MAGENTA.r * g3;
                float g = COL_VOID.g + COL_CYAN.g * g1 + COL_VIOLET.g * g2 + COL_MAGENTA.g * g3;
                float b = COL_VOID.b + COL_CYAN.b * g1 + COL_VIOLET.b * g2 + COL_MAGENTA.b * g3;

                // Subtle futuristic Web3 coordinate micro-dots
                if (gy && (x % 32 == 0)) {
                    r += 16.0f; g += 26.0f; b += 40.0f;
                }
                row[x] = pack_bgra(clamp_u8(r), clamp_u8(g), clamp_u8(b));
            }
        }
    }

    // Separable 2-pass sliding-window box blur on region (approximates smooth Gaussian blur in O(W*H))
    void blur_region(int rx, int ry, int rw, int rh, int radius) {
        int x0 = std::max(0, rx);
        int y0 = std::max(0, ry);
        int x1 = std::min(w, rx + rw);
        int y1 = std::min(h, ry + rh);
        if (x1 <= x0 || y1 <= y0 || radius < 1) return;

        int bw = x1 - x0;
        int bh = y1 - y0;
        for (int y = 0; y < bh; ++y) {
            std::memcpy(&scratch[static_cast<size_t>(y) * bw],
                        &pixels[static_cast<size_t>(y0 + y) * w + x0],
                        static_cast<size_t>(bw) * sizeof(uint32_t));
        }

        for (int pass = 0; pass < 2; ++pass) {
            // Horizontal pass: scratch -> blur_tmp
            for (int y = 0; y < bh; ++y) {
                const uint32_t *src = &scratch[static_cast<size_t>(y) * bw];
                uint32_t *dst = &blur_tmp[static_cast<size_t>(y) * bw];
                int sr = 0, sg = 0, sb = 0, cnt = 0;
                for (int k = 0; k <= std::min(radius, bw - 1); ++k) {
                    uint32_t p = src[k];
                    sr += (p >> 16) & 0xFF; sg += (p >> 8) & 0xFF; sb += p & 0xFF; cnt++;
                }
                for (int x = 0; x < bw; ++x) {
                    dst[x] = pack_bgra(static_cast<uint8_t>(sr / cnt),
                                       static_cast<uint8_t>(sg / cnt),
                                       static_cast<uint8_t>(sb / cnt));
                    int add_i = x + radius + 1;
                    if (add_i < bw) {
                        uint32_t p = src[add_i];
                        sr += (p >> 16) & 0xFF; sg += (p >> 8) & 0xFF; sb += p & 0xFF; cnt++;
                    }
                    int rem_i = x - radius;
                    if (rem_i >= 0) {
                        uint32_t p = src[rem_i];
                        sr -= (p >> 16) & 0xFF; sg -= (p >> 8) & 0xFF; sb -= p & 0xFF; cnt--;
                    }
                }
            }
            // Vertical pass: blur_tmp -> scratch
            for (int x = 0; x < bw; ++x) {
                int sr = 0, sg = 0, sb = 0, cnt = 0;
                for (int k = 0; k <= std::min(radius, bh - 1); ++k) {
                    uint32_t p = blur_tmp[static_cast<size_t>(k) * bw + x];
                    sr += (p >> 16) & 0xFF; sg += (p >> 8) & 0xFF; sb += p & 0xFF; cnt++;
                }
                for (int y = 0; y < bh; ++y) {
                    scratch[static_cast<size_t>(y) * bw + x] = pack_bgra(
                        static_cast<uint8_t>(sr / cnt),
                        static_cast<uint8_t>(sg / cnt),
                        static_cast<uint8_t>(sb / cnt));
                    int add_i = y + radius + 1;
                    if (add_i < bh) {
                        uint32_t p = blur_tmp[static_cast<size_t>(add_i) * bw + x];
                        sr += (p >> 16) & 0xFF; sg += (p >> 8) & 0xFF; sb += p & 0xFF; cnt++;
                    }
                    int rem_i = y - radius;
                    if (rem_i >= 0) {
                        uint32_t p = blur_tmp[static_cast<size_t>(rem_i) * bw + x];
                        sr -= (p >> 16) & 0xFF; sg -= (p >> 8) & 0xFF; sb -= p & 0xFF; cnt--;
                    }
                }
            }
        }
    }

    // Authentic frosted glass card: optical Gaussian blur + obsidian tint + micro-grain + specular neon rim
    void draw_glass_card(Rect rc, float radius, bool elevated, bool active_rim) {
        int x0 = std::max(0, rc.x);
        int y0 = std::max(0, rc.y);
        int x1 = std::min(w, rc.x + rc.w);
        int y1 = std::min(h, rc.y + rc.h);
        if (x1 <= x0 || y1 <= y0) return;

        blur_region(x0, y0, x1 - x0, y1 - y0, elevated ? 16 : 12);

        Color tint = elevated ? COL_GLASS_ELEV : COL_GLASS_SURF;
        float tint_a = tint.a / 255.0f;
        float cx = rc.x + rc.w * 0.5f;
        float cy = rc.y + rc.h * 0.5f;
        float hw = rc.w * 0.5f;
        float hh = rc.h * 0.5f;
        int bw = x1 - x0;

        for (int y = y0; y < y1; ++y) {
            uint32_t *row = &pixels[static_cast<size_t>(y) * w];
            const uint32_t *brow = &scratch[static_cast<size_t>(y - y0) * bw];
            float ny = static_cast<float>(y - rc.y) / std::max(1, rc.h);
            for (int x = x0; x < x1; ++x) {
                float d = sd_rounded_box(x + 0.5f, y + 0.5f, cx, cy, hw, hh, radius);
                if (d > 1.2f) continue;

                float cov = std::clamp(0.75f - d, 0.0f, 1.0f);
                uint32_t bg_blur = brow[x - x0];
                // Deterministic subtle frosted-glass micro-grain
                uint32_t hash = static_cast<uint32_t>(x * 374761393u ^ y * 668265263u);
                float grain = ((hash >> 24) & 7) - 3.5f;
                // Top inner specular highlight
                float sheen = (ny < 0.14f) ? (0.14f - ny) * 0.45f : 0.0f;

                float br = ((bg_blur >> 16) & 0xFF) * (1.0f - tint_a) + tint.r * tint_a + grain + 255.0f * sheen;
                float bg = ((bg_blur >> 8) & 0xFF) * (1.0f - tint_a) + tint.g * tint_a + grain + 255.0f * sheen;
                float bb = (bg_blur & 0xFF) * (1.0f - tint_a) + tint.b * tint_a + grain + 255.0f * sheen;
                Color frosted{clamp_u8(br), clamp_u8(bg), clamp_u8(bb), 255};
                blend_pixel(row[x], frosted, cov);

                // Anti-aliased 1.2px specular neon glass border
                if (d > -1.4f && d < 0.9f) {
                    float edge_cov = 1.0f - std::fabs(d + 0.25f) / 1.15f;
                    edge_cov = std::clamp(edge_cov, 0.0f, 1.0f);
                    float nx = static_cast<float>(x - rc.x) / std::max(1, rc.w);
                    float gpos = (nx + ny) * 0.5f;
                    Color rim = active_rim ? lerp_col(COL_CYAN, COL_VIOLET, gpos)
                                           : lerp_col({170, 235, 255, 255}, {140, 120, 210, 255}, gpos);
                    float rim_alpha = active_rim ? 0.72f : 0.24f;
                    blend_pixel(row[x], rim, edge_cov * rim_alpha);
                }
            }
        }
    }

    void draw_gradient_pill(Rect rc, float radius, Color a, Color b, float alpha = 1.0f) {
        int x0 = std::max(0, rc.x), y0 = std::max(0, rc.y);
        int x1 = std::min(w, rc.x + rc.w), y1 = std::min(h, rc.y + rc.h);
        float cx = rc.x + rc.w * 0.5f, cy = rc.y + rc.h * 0.5f;
        float hw = rc.w * 0.5f, hh = rc.h * 0.5f;
        for (int y = y0; y < y1; ++y) {
            uint32_t *row = &pixels[static_cast<size_t>(y) * w];
            for (int x = x0; x < x1; ++x) {
                float d = sd_rounded_box(x + 0.5f, y + 0.5f, cx, cy, hw, hh, radius);
                if (d > 1.0f) continue;
                float cov = std::clamp(0.75f - d, 0.0f, 1.0f) * alpha;
                float t = static_cast<float>(x - rc.x) / std::max(1, rc.w);
                blend_pixel(row[x], lerp_col(a, b, t), cov);
            }
        }
    }

    void draw_input_box(Rect rc, bool focused) {
        draw_gradient_pill(rc, 10.0f, COL_GLASS_INPUT, COL_GLASS_INPUT, 0.85f);
        // Subtle 1px focus rim
        int x0 = std::max(0, rc.x), y0 = std::max(0, rc.y);
        int x1 = std::min(w, rc.x + rc.w), y1 = std::min(h, rc.y + rc.h);
        float cx = rc.x + rc.w * 0.5f, cy = rc.y + rc.h * 0.5f;
        float hw = rc.w * 0.5f, hh = rc.h * 0.5f;
        for (int y = y0; y < y1; ++y) {
            uint32_t *row = &pixels[static_cast<size_t>(y) * w];
            for (int x = x0; x < x1; ++x) {
                float d = sd_rounded_box(x + 0.5f, y + 0.5f, cx, cy, hw, hh, 10.0f);
                if (d > -1.3f && d < 0.8f) {
                    float ec = std::clamp(1.0f - std::fabs(d + 0.25f) / 1.05f, 0.0f, 1.0f);
                    blend_pixel(row[x], focused ? COL_CYAN : COL_TEXT_MUTED, ec * (focused ? 0.85f : 0.30f));
                }
            }
        }
    }

    void draw_sparkline(Rect rc, const double *samples, int count) {
        if (rc.w < 20 || rc.h < 20 || count < 2) return;
        double max_v = 1.0;
        for (int i = 0; i < count; ++i) max_v = std::max(max_v, samples[i]);

        // Horizontal faint grid lines
        for (int g = 1; g <= 3; ++g) {
            int gy = rc.y + rc.h * g / 4;
            if (gy >= 0 && gy < h) {
                for (int x = rc.x; x < rc.x + rc.w && x < w; ++x) {
                    blend_pixel(pixels[static_cast<size_t>(gy) * w + x], COL_TEXT_MUTED, 0.14f);
                }
            }
        }

        // Smooth linear interpolated area fill + luminous 2px top curve
        for (int ix = 0; ix < rc.w; ++ix) {
            int x = rc.x + ix;
            if (x < 0 || x >= w) continue;
            float fidx = static_cast<float>(ix) * (count - 1) / std::max(1, rc.w - 1);
            int i0 = static_cast<int>(fidx);
            int i1 = std::min(i0 + 1, count - 1);
            float frac = fidx - i0;
            double v = samples[i0] * (1.0 - frac) + samples[i1] * frac;
            float norm = static_cast<float>(std::clamp(v / max_v, 0.0, 1.0));
            float curve_y = rc.y + rc.h - 4.0f - norm * (rc.h - 10.0f);
            Color stroke = lerp_col(COL_CYAN, COL_VIOLET, static_cast<float>(ix) / std::max(1, rc.w));

            int y_start = std::max(rc.y, static_cast<int>(curve_y) - 2);
            int y_end   = std::min(h - 1, rc.y + rc.h - 1);
            for (int y = y_start; y <= y_end; ++y) {
                float dy = y - curve_y;
                if (dy < -1.8f) continue;
                if (std::fabs(dy) <= 1.6f) {
                    float a = std::clamp(1.0f - std::fabs(dy) / 1.6f, 0.0f, 1.0f);
                    blend_pixel(pixels[static_cast<size_t>(y) * w + x], stroke, a * 0.95f);
                } else if (dy > 0.0f) {
                    float depth = 1.0f - dy / std::max(1.0f, static_cast<float>(rc.y + rc.h - curve_y));
                    blend_pixel(pixels[static_cast<size_t>(y) * w + x], stroke, std::clamp(depth, 0.0f, 1.0f) * 0.30f);
                }
            }
        }
    }

    // Glowing hexagonal OpenFIR Web3 emblem
    void draw_hex_logo(int cx, int cy, float rad) {
        int r_int = static_cast<int>(rad) + 4;
        for (int y = std::max(0, cy - r_int); y < std::min(h, cy + r_int); ++y) {
            for (int x = std::max(0, cx - r_int); x < std::min(w, cx + r_int); ++x) {
                float px = std::fabs(x - cx);
                float py = std::fabs(y - cy);
                float d = std::max(px * 0.866025f + py * 0.5f, py) - rad;
                if (d < 2.5f) {
                    float t = static_cast<float>(x - (cx - r_int)) / std::max(1, 2 * r_int);
                    Color col = lerp_col(COL_CYAN, COL_VIOLET, t);
                    if (d <= 0.0f && d > -3.2f) {
                        blend_pixel(pixels[static_cast<size_t>(y) * w + x], col, 0.95f);
                    } else if (d <= -3.2f) {
                        blend_pixel(pixels[static_cast<size_t>(y) * w + x], col, 0.25f);
                    } else {
                        blend_pixel(pixels[static_cast<size_t>(y) * w + x], col, (1.0f - d / 2.5f) * 0.35f);
                    }
                }
            }
        }
    }
};

// ============================================================================
// JSON Helpers & Engine State
// ============================================================================
bool json_str(const char *j, const char *k, std::string &out) {
    std::string pat = std::string("\"") + k + "\":\"";
    const char *p = std::strstr(j, pat.c_str());
    if (!p) return false;
    p += pat.size();
    out.clear();
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) ++p;
        out.push_back(*p++);
    }
    return true;
}

double json_num(const char *j, const char *k, double def) {
    std::string pat = std::string("\"") + k + "\":";
    const char *p = std::strstr(j, pat.c_str());
    if (!p) return def;
    p += pat.size();
    char *end = nullptr;
    double v = std::strtod(p, &end);
    return (end != p) ? v : def;
}

std::string json_esc(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(c); }
        else if (static_cast<unsigned char>(c) >= 0x20) out.push_back(c);
    }
    return out;
}

std::string fmt_bytes(int64_t b) {
    char buf[48];
    if (b >= 1024LL * 1024 * 1024) std::snprintf(buf, sizeof(buf), "%.2f GiB", b / (1024.0 * 1024.0 * 1024.0));
    else if (b >= 1024LL * 1024)   std::snprintf(buf, sizeof(buf), "%.2f MiB", b / (1024.0 * 1024.0));
    else if (b >= 1024LL)          std::snprintf(buf, sizeof(buf), "%.1f KiB", b / 1024.0);
    else                           std::snprintf(buf, sizeof(buf), "%lld B", static_cast<long long>(b));
    return buf;
}

enum class Tab { Push = 0, Pull = 1, Server = 2, Audit = 3 };

struct DirEntry {
    std::string name;
    bool is_dir = false;
    int64_t size = 0;
};

struct GuiState {
    std::mutex mu;
    Tab tab = Tab::Push;
    int focus_field = 0;

    std::string server_addr = "127.0.0.1:9900";
    std::string secret;
    std::string file_path;
    std::string out_dir = "./openfir_data";
    std::string listen_addr = ":9900";
    int transport_idx = 0; // 0=auto, 1=udp, 2=tcp
    int tcp_streams = 4;
    int max_mbps = 1000;
    bool overwrite = true;

    uint64_t active_job = 0;
    uint64_t server_handle = 0;
    std::string server_status = "Server standby — ready to bind TLS 1.3 + UDP";

    std::string phase = "idle";
    std::string message = "Ready · Hybrid TLS 1.3 + UDP GSO/GF(256) RS + Rabin CDC";
    std::string active_lane = "STANDBY";
    std::string merkle_hex;
    double percent = 0.0;
    double goodput_mbps = 0.0;
    double instant_mbps = 0.0;
    double rtt_ms = 0.0;
    int64_t bytes_done = 0;
    int64_t total_bytes = 0;
    uint64_t wire_udp = 0;
    uint64_t wire_tcp = 0;
    uint32_t cas_blocks = 0;
    uint32_t zero_blocks = 0;
    uint32_t comp_blocks = 0;
    uint32_t fec_recovered = 0;
    uint32_t failover_blocks = 0;
    int suite_idx = 0;
    double spark[60]{};

    // Modal POSIX File Browser
    bool browser_open = false;
    bool browser_for_dir = false;
    std::string browser_cwd = ".";
    std::vector<DirEntry> browser_items;
    int browser_scroll = 0;

    // Interactive layout hitboxes (computed during render)
    Rect rc_tabs[4];
    Rect rc_fields[4];
    Rect rc_keygen;
    Rect rc_browse;
    Rect rc_modes[3];
    Rect rc_overwrite;
    Rect rc_cta;
    Rect rc_modal_select_dir;
    Rect rc_modal_close;
    Rect rc_modal_list;
};

void on_engine_event(uint64_t handle, const char *json, void *ctx) {
    auto *st = static_cast<GuiState *>(ctx);
    if (!st || !json) return;

    std::string op, phase, msg, lane, merkle;
    json_str(json, "op", op);
    json_str(json, "phase", phase);
    json_str(json, "message", msg);
    json_str(json, "active_lane", lane);
    json_str(json, "merkle_root_hex", merkle);

    std::lock_guard<std::mutex> lk(st->mu);
    if (op == "server") {
        if (phase == "listening") {
            st->server_status = msg;
            st->phase = "listening";
            st->message = msg;
        } else if (phase == "error") {
            st->server_handle = 0;
            st->server_status = "ERROR: " + msg;
            st->phase = "error";
            st->message = msg;
        }
        return;
    }
    if (handle != 0 && st->active_job != 0 && handle != st->active_job) return;

    if (!phase.empty()) st->phase = phase;
    if (!msg.empty()) st->message = msg;
    if (!lane.empty()) st->active_lane = lane;
    if (!merkle.empty()) st->merkle_hex = merkle;

    st->percent         = json_num(json, "percent", st->percent);
    st->goodput_mbps    = json_num(json, "goodput_mbps", st->goodput_mbps);
    st->instant_mbps    = json_num(json, "instant_mbps", st->instant_mbps);
    st->rtt_ms          = json_num(json, "rtt_ms", st->rtt_ms);
    st->bytes_done      = static_cast<int64_t>(json_num(json, "bytes_done", static_cast<double>(st->bytes_done)));
    st->total_bytes     = static_cast<int64_t>(json_num(json, "total_bytes", static_cast<double>(st->total_bytes)));
    st->wire_udp        = static_cast<uint64_t>(json_num(json, "wire_udp_bytes", static_cast<double>(st->wire_udp)));
    st->wire_tcp        = static_cast<uint64_t>(json_num(json, "wire_tcp_bytes", static_cast<double>(st->wire_tcp)));
    st->cas_blocks      = static_cast<uint32_t>(json_num(json, "cas_blocks", static_cast<double>(st->cas_blocks)));
    st->zero_blocks     = static_cast<uint32_t>(json_num(json, "zero_blocks", static_cast<double>(st->zero_blocks)));
    st->comp_blocks     = static_cast<uint32_t>(json_num(json, "compressed_blocks", static_cast<double>(st->comp_blocks)));
    st->fec_recovered   = static_cast<uint32_t>(json_num(json, "fec_recovered", static_cast<double>(st->fec_recovered)));
    st->failover_blocks = static_cast<uint32_t>(json_num(json, "udp_fallback_blocks", static_cast<double>(st->failover_blocks)));
    st->suite_idx       = static_cast<int>(json_num(json, "suite_index", static_cast<double>(st->suite_idx)));

    if (phase == "transferring" || phase == "done") {
        std::memmove(&st->spark[0], &st->spark[1], sizeof(st->spark) - sizeof(st->spark[0]));
        st->spark[59] = st->instant_mbps > 0.01 ? st->instant_mbps : st->goodput_mbps;
    }
    if (phase == "done" || phase == "error") {
        st->active_job = 0;
    }
}

void do_keygen(GuiState &st) {
    char key[80]{};
    if (openfir_keygen(key, sizeof(key)) == 64) {
        std::lock_guard<std::mutex> lk(st.mu);
        st.secret = key;
        st.message = "Generated fresh 256-bit cryptographically secure shared secret";
    }
}

void load_browser(GuiState &st, const std::string &dir) {
    DIR *dp = opendir(dir.c_str());
    if (!dp) return;
    st.browser_items.clear();
    struct dirent *de = nullptr;
    while ((de = readdir(dp)) != nullptr) {
        if (std::strcmp(de->d_name, ".") == 0) continue;
        DirEntry e;
        e.name = de->d_name;
        std::string full = (dir == "/" ? "/" : dir + "/") + e.name;
        struct stat sb{};
        if (stat(full.c_str(), &sb) == 0) {
            e.is_dir = S_ISDIR(sb.st_mode);
            e.size = sb.st_size;
        }
        st.browser_items.push_back(std::move(e));
    }
    closedir(dp);
    std::sort(st.browser_items.begin(), st.browser_items.end(), [](const DirEntry &a, const DirEntry &b) {
        if (a.name == "..") return true;
        if (b.name == "..") return false;
        if (a.is_dir != b.is_dir) return a.is_dir;
        return a.name < b.name;
    });
    st.browser_scroll = 0;
}

void trigger_cta(GuiState &st) {
    std::unique_lock<std::mutex> lk(st.mu);
    if (st.tab == Tab::Server) {
        if (st.server_handle != 0) {
            uint64_t h = st.server_handle;
            st.server_handle = 0;
            st.phase = "idle";
            st.server_status = "Server stopped";
            st.message = "Dual-stack server stopped cleanly";
            lk.unlock();
            openfir_server_stop(h);
            return;
        }
        std::string cfg = "{\"listen\":\"" + json_esc(st.listen_addr) +
                          "\",\"dir\":\"" + json_esc(st.out_dir) +
                          "\",\"secret\":\"" + json_esc(st.secret) +
                          "\",\"overwrite\":" + (st.overwrite ? "true" : "false") +
                          ",\"max_sessions\":64}";
        lk.unlock();
        uint64_t h = openfir_server_start(cfg.c_str(), on_engine_event, &st);
        lk.lock();
        st.server_handle = h;
        return;
    }

    if (st.active_job != 0) {
        uint64_t j = st.active_job;
        st.active_job = 0;
        st.phase = "idle";
        st.message = "Transfer cancellation requested...";
        lk.unlock();
        openfir_transfer_cancel(j);
        return;
    }

    st.percent = 0.0; st.goodput_mbps = 0.0; st.instant_mbps = 0.0;
    st.bytes_done = 0; st.total_bytes = 0; st.wire_udp = 0; st.wire_tcp = 0;
    st.cas_blocks = 0; st.zero_blocks = 0; st.comp_blocks = 0;
    st.fec_recovered = 0; st.failover_blocks = 0; st.merkle_hex.clear();
    std::memset(st.spark, 0, sizeof(st.spark));

    if (st.tab == Tab::Audit) {
        st.phase = "transferring";
        st.message = "Running 4-Suite Enterprise Protocol Audit...";
        lk.unlock();
        uint64_t j = openfir_selftest_start(on_engine_event, &st);
        lk.lock();
        st.active_job = j;
        return;
    }

    static const char *modes[3] = {"auto", "udp", "tcp"};
    std::string cfg = std::string("{\"op\":\"") + (st.tab == Tab::Push ? "push" : "pull") +
                      "\",\"server\":\"" + json_esc(st.server_addr) +
                      "\",\"secret\":\"" + json_esc(st.secret) +
                      "\",\"file\":\"" + json_esc(st.file_path) +
                      "\",\"dir\":\"" + json_esc(st.out_dir) +
                      "\",\"transport\":\"" + modes[st.transport_idx % 3] +
                      "\",\"tcp_streams\":" + std::to_string(st.tcp_streams) +
                      ",\"max_mbps\":" + std::to_string(st.max_mbps) +
                      ",\"overwrite\":" + (st.overwrite ? "true" : "false") + "}";
    st.phase = "handshake";
    lk.unlock();
    uint64_t j = openfir_transfer_start(cfg.c_str(), on_engine_event, &st);
    lk.lock();
    if (j != 0) st.active_job = j;
}

// ============================================================================
// Pure X11 + Xft Text Overlay & Frame Composition
// ============================================================================
struct TextDraw {
    int x, y;
    std::string text;
    Color col;
    int font_idx; // 0=body, 1=bold, 2=title, 3=mono
};

void compose_scene(GlassSurface &surf, GuiState &st, float t, std::vector<TextDraw> &texts) {
    texts.clear();
    surf.draw_aurora_backdrop(t);

    std::lock_guard<std::mutex> lk(st.mu);
    const int W = surf.w, H = surf.h;
    const int pad = 20;

    // 1. Header Glass Bar
    Rect header{pad, 16, W - 2 * pad, 62};
    surf.draw_glass_card(header, 18.0f, true, true);
    surf.draw_hex_logo(header.x + 30, header.y + 31, 15.0f);
    texts.push_back({header.x + 56, header.y + 36, "OPENFIR", COL_TEXT_PRI, 2});
    texts.push_back({header.x + 152, header.y + 35, "v1.1 FROST", COL_CYAN, 1});

    const char *tab_labels[4] = {"PUSH", "PULL", "SERVER", "AUDIT"};
    int tx = header.x + 258;
    for (int i = 0; i < 4; ++i) {
        Rect r{tx, header.y + 13, 94, 36};
        st.rc_tabs[i] = r;
        bool act = (static_cast<int>(st.tab) == i);
        if (act) surf.draw_gradient_pill(r, 18.0f, COL_CYAN, COL_ACCENT_END, 0.95f);
        else     surf.draw_gradient_pill(r, 18.0f, COL_GLASS_ELEV, COL_GLASS_ELEV, 0.55f);
        texts.push_back({r.x + 22, r.y + 23, tab_labels[i], act ? COL_VOID : COL_TEXT_SEC, 1});
        tx += 104;
    }

    Color badge_col = COL_TEXT_SEC;
    std::string badge_txt = "IDLE";
    if (st.phase == "done") { badge_col = COL_MINT; badge_txt = "MERKLE VERIFIED"; }
    else if (st.phase == "listening") { badge_col = COL_MINT; badge_txt = "SERVER LIVE"; }
    else if (st.phase == "transferring" || st.phase == "handshake") { badge_col = COL_CYAN; badge_txt = "STREAM ACTIVE"; }
    else if (st.phase == "error") { badge_col = COL_ROSE; badge_txt = "ERROR"; }
    Rect badge{header.x + header.w - 178, header.y + 16, 160, 30};
    surf.draw_gradient_pill(badge, 15.0f, COL_GLASS_INPUT, COL_GLASS_INPUT, 0.85f);
    texts.push_back({badge.x + 16, badge.y + 20, "● " + badge_txt, badge_col, 1});

    // 2. Main Split Frosted Workspace
    int body_y = 94;
    int body_h = H - body_y - 20;
    int left_w = (W - 3 * pad) * 46 / 100;
    Rect left_card{pad, body_y, left_w, body_h};
    Rect right_card{pad * 2 + left_w, body_y, W - 3 * pad - left_w, body_h};

    surf.draw_glass_card(left_card, 20.0f, false, true);
    surf.draw_glass_card(right_card, 20.0f, false, false);

    // Reset dynamic hitboxes
    for (auto &f : st.rc_fields) f = {};
    st.rc_keygen = {}; st.rc_browse = {}; st.rc_overwrite = {};
    for (auto &m : st.rc_modes) m = {};

    int fx = left_card.x + 22;
    int fw = left_card.w - 44;
    int fy = left_card.y + 26;

    std::string card_hdr = st.tab == Tab::Push ? "PUSH · HYBRID UPLOAD" :
                           st.tab == Tab::Pull ? "PULL · MERKLE DOWNLOAD" :
                           st.tab == Tab::Server ? "SERVER · DUAL-STACK TLS 1.3 + UDP" :
                           "AUDIT · 4-SUITE CRYPTO VERIFICATION";
    texts.push_back({fx, fy, card_hdr, COL_CYAN, 1});
    fy += 28;

    auto draw_field = [&](int idx, const std::string &lbl, const std::string &val, int extra_right_w) {
        texts.push_back({fx, fy, lbl, st.focus_field == idx ? COL_CYAN : COL_TEXT_SEC, 0});
        Rect box{fx, fy + 8, fw - extra_right_w, 36};
        st.rc_fields[idx] = box;
        surf.draw_input_box(box, st.focus_field == idx);
        std::string shown = val.empty() ? "(click to enter)" : val;
        if (shown.size() > 42) shown = "..." + shown.substr(shown.size() - 39);
        if (st.focus_field == idx) shown += "|";
        texts.push_back({box.x + 12, box.y + 23, shown, val.empty() ? COL_TEXT_MUTED : COL_TEXT_MONO, 3});
        fy += 60;
    };

    if (st.tab == Tab::Push || st.tab == Tab::Pull) {
        draw_field(0, "SERVER ENDPOINT (host:port)", st.server_addr, 0);
        int ky = fy + 8;
        draw_field(1, "256-BIT SHARED SECRET", st.secret, 94);
        st.rc_keygen = {fx + fw - 86, ky, 86, 36};
        surf.draw_gradient_pill(st.rc_keygen, 10.0f, COL_GLASS_ELEV, COL_VIOLET, 0.72f);
        texts.push_back({st.rc_keygen.x + 15, st.rc_keygen.y + 23, "KEYGEN", COL_TEXT_PRI, 1});

        int by = fy + 8;
        draw_field(2, st.tab == Tab::Push ? "LOCAL FILE / DIRECTORY" : "REMOTE FILE / DIRECTORY NAME",
                   st.file_path, st.tab == Tab::Push ? 94 : 0);
        if (st.tab == Tab::Push) {
            st.rc_browse = {fx + fw - 86, by, 86, 36};
            surf.draw_gradient_pill(st.rc_browse, 10.0f, COL_GLASS_ELEV, COL_CYAN, 0.55f);
            texts.push_back({st.rc_browse.x + 14, st.rc_browse.y + 23, "BROWSE", COL_TEXT_PRI, 1});
        } else {
            int dy = fy + 8;
            draw_field(3, "LOCAL OUTPUT DIRECTORY", st.out_dir, 94);
            st.rc_browse = {fx + fw - 86, dy, 86, 36};
            surf.draw_gradient_pill(st.rc_browse, 10.0f, COL_GLASS_ELEV, COL_CYAN, 0.55f);
            texts.push_back({st.rc_browse.x + 14, st.rc_browse.y + 23, "BROWSE", COL_TEXT_PRI, 1});
        }

        texts.push_back({fx, fy, "TRANSPORT DATA PLANE", COL_TEXT_SEC, 0});
        const char *ml[3] = {"AUTO HYBRID", "UDP GSO", "TLS 1.3 TCP"};
        int mw = (fw - 16) / 3;
        for (int i = 0; i < 3; ++i) {
            Rect mr{fx + i * (mw + 8), fy + 10, mw, 34};
            st.rc_modes[i] = mr;
            bool act = (st.transport_idx == i);
            surf.draw_gradient_pill(mr, 10.0f, act ? COL_CYAN : COL_GLASS_INPUT,
                                    act ? COL_ACCENT_END : COL_GLASS_INPUT, act ? 0.95f : 0.80f);
            texts.push_back({mr.x + 14, mr.y + 22, ml[i], act ? COL_VOID : COL_TEXT_SEC, 1});
        }
        fy += 60;

        st.rc_overwrite = {fx, fy, fw, 32};
        surf.draw_gradient_pill({fx, fy + 4, 44, 22}, 11.0f,
                                st.overwrite ? COL_MINT : COL_GLASS_INPUT,
                                st.overwrite ? COL_CYAN : COL_GLASS_INPUT, 0.9f);
        texts.push_back({fx + 56, fy + 20,
                         std::string("Allow Overwrite: ") + (st.overwrite ? "ON" : "OFF") +
                         "  ·  4 TLS Lanes  ·  1000 MiB/s",
                         COL_TEXT_SEC, 0});
    } else if (st.tab == Tab::Server) {
        draw_field(0, "LISTEN ADDRESS (:9900 or :443)", st.listen_addr, 0);
        int dy = fy + 8;
        draw_field(1, "STORAGE ROOT DIRECTORY", st.out_dir, 94);
        st.rc_browse = {fx + fw - 86, dy, 86, 36};
        surf.draw_gradient_pill(st.rc_browse, 10.0f, COL_GLASS_ELEV, COL_CYAN, 0.55f);
        texts.push_back({st.rc_browse.x + 14, st.rc_browse.y + 23, "BROWSE", COL_TEXT_PRI, 1});

        int ky = fy + 8;
        draw_field(2, "SERVER 256-BIT SECRET", st.secret, 94);
        st.rc_keygen = {fx + fw - 86, ky, 86, 36};
        surf.draw_gradient_pill(st.rc_keygen, 10.0f, COL_GLASS_ELEV, COL_VIOLET, 0.72f);
        texts.push_back({st.rc_keygen.x + 15, st.rc_keygen.y + 23, "KEYGEN", COL_TEXT_PRI, 1});

        texts.push_back({fx, fy + 16, st.server_status, st.server_handle ? COL_MINT : COL_TEXT_SEC, 0});
    } else {
        texts.push_back({fx, fy + 4,  "Zero-Dependency In-Process Protocol Audit:", COL_TEXT_PRI, 1});
        texts.push_back({fx, fy + 36, "• Suite 1: 4 MiB Hybrid Auto Push + Pull (DEFLATE/Zero/Raw)", st.suite_idx >= 1 ? COL_CYAN : COL_TEXT_SEC, 0});
        texts.push_back({fx, fy + 64, "• Suite 2: 17B Shift-Resistant Rabin CDC Cross-Session CAS", st.suite_idx >= 2 ? COL_CYAN : COL_TEXT_SEC, 0});
        texts.push_back({fx, fy + 92, "• Suite 3: 10% Burst-Loss Pure UDP + GF(256) RS FEC", st.suite_idx >= 3 ? COL_CYAN : COL_TEXT_SEC, 0});
        texts.push_back({fx, fy + 120,"• Suite 4: ISP UDP Blackhole -> TLS 1.3 TCP Auto-Failover", st.suite_idx >= 4 ? COL_MINT : COL_TEXT_SEC, 0});
        texts.push_back({fx, fy + 162,"100% Apache-2.0 clean-room code · Zero third-party libraries", COL_TEXT_MUTED, 0});
    }

    // Primary Gradient CTA Button
    st.rc_cta = {fx, left_card.y + left_card.h - 62, fw, 44};
    bool is_stop = (st.tab == Tab::Server && st.server_handle != 0) || (st.tab != Tab::Server && st.active_job != 0);
    surf.draw_gradient_pill(st.rc_cta, 12.0f,
                            is_stop ? COL_ROSE : (st.tab == Tab::Server ? COL_MINT : COL_CYAN),
                            is_stop ? COL_MAGENTA : (st.tab == Tab::Server ? COL_CYAN : COL_ACCENT_END),
                            0.96f);
    std::string cta_txt = st.tab == Tab::Server ? (st.server_handle ? "STOP DUAL-STACK SERVER" : "START DUAL-STACK SERVER") :
                          st.active_job ? "CANCEL ACTIVE TRANSFER" :
                          st.tab == Tab::Push ? "LAUNCH HYBRID PUSH" :
                          st.tab == Tab::Pull ? "LAUNCH MERKLE PULL" : "RUN 4-SUITE PROTOCOL AUDIT";
    texts.push_back({st.rc_cta.x + 28, st.rc_cta.y + 28, cta_txt, COL_VOID, 1});

    // 3. Right Frosted Telemetry Card
    int rx = right_card.x + 22;
    int rw = right_card.w - 44;
    int ry = right_card.y + 26;
    texts.push_back({rx, ry, "LIVE TELEMETRY · ZERO-COPY ENGINE", COL_VIOLET, 1});

    char pct_buf[128];
    std::snprintf(pct_buf, sizeof(pct_buf), "%.1f%%   ·   %s / %s   ·   %s",
                  st.percent, fmt_bytes(st.bytes_done).c_str(), fmt_bytes(st.total_bytes).c_str(),
                  st.active_lane.c_str());
    texts.push_back({rx, ry + 32, pct_buf, COL_TEXT_PRI, 1});

    // Neon Progress Bar
    Rect pbar{rx, ry + 46, rw, 14};
    surf.draw_gradient_pill(pbar, 7.0f, COL_GLASS_INPUT, COL_GLASS_INPUT, 0.90f);
    int fill_w = static_cast<int>(pbar.w * std::clamp(st.percent, 0.0, 100.0) / 100.0);
    if (fill_w > 4) {
        surf.draw_gradient_pill({pbar.x, pbar.y, fill_w, pbar.h}, 7.0f, COL_CYAN, COL_ACCENT_END, 0.98f);
    }

    // 4 Frosted KPI Micro-Tiles (2x2 Grid)
    int ky = ry + 78;
    int tw = (rw - 14) / 2;
    char k1[64], k2[64], k3[64], k4[64];
    std::snprintf(k1, sizeof(k1), "%.2f MiB/s", st.goodput_mbps);
    std::snprintf(k2, sizeof(k2), "UDP %s · TCP %s", fmt_bytes(static_cast<int64_t>(st.wire_udp)).c_str(),
                  fmt_bytes(static_cast<int64_t>(st.wire_tcp)).c_str());
    std::snprintf(k3, sizeof(k3), "CAS %u · Zero %u · Deflate %u", st.cas_blocks, st.zero_blocks, st.comp_blocks);
    std::snprintf(k4, sizeof(k4), "Rec %u · FO %u · %.1f ms", st.fec_recovered, st.failover_blocks, st.rtt_ms);

    struct Kpi { Rect r; const char *lbl; const char *val; Color vc; };
    Kpi kpis[4] = {
        {{rx,          ky,      tw, 68}, "EFFECTIVE GOODPUT", k1, COL_CYAN},
        {{rx + tw + 14, ky,     rw - tw - 14, 68}, "HYBRID WIRE I/O", k2, COL_TEXT_MONO},
        {{rx,          ky + 80, tw, 68}, "RABIN CDC CAS / DEDUP", k3, COL_MINT},
        {{rx + tw + 14, ky + 80, rw - tw - 14, 68}, "GF(256) RS FEC & RTT", k4,
         (st.fec_recovered || st.failover_blocks) ? COL_AMBER : COL_TEXT_PRI},
    };
    for (const auto &kp : kpis) {
        surf.draw_glass_card(kp.r, 14.0f, true, false);
        texts.push_back({kp.r.x + 14, kp.r.y + 24, kp.lbl, COL_TEXT_SEC, 0});
        texts.push_back({kp.r.x + 14, kp.r.y + 50, kp.val, kp.vc, 1});
    }

    // Live Neon Sparkline Chart Card
    int sp_y = ky + 164;
    int sp_h = std::max(90, (right_card.y + right_card.h - 76) - sp_y);
    Rect sp_card{rx, sp_y, rw, sp_h};
    surf.draw_glass_card(sp_card, 14.0f, true, false);
    texts.push_back({sp_card.x + 14, sp_card.y + 22, "REAL-TIME THROUGHPUT SPARKLINE (MiB/s)", COL_TEXT_SEC, 0});
    surf.draw_sparkline({sp_card.x + 12, sp_card.y + 30, sp_card.w - 24, sp_card.h - 40}, st.spark, 60);

    // Cryptographic Merkle Root Strip
    Rect mk_rc{rx, right_card.y + right_card.h - 58, rw, 40};
    surf.draw_gradient_pill(mk_rc, 10.0f, COL_GLASS_INPUT, COL_GLASS_INPUT, 0.88f);
    if (!st.merkle_hex.empty()) {
        texts.push_back({mk_rc.x + 14, mk_rc.y + 25, "✓ MERKLE SHA-256: " + st.merkle_hex.substr(0, 44) + "...", COL_MINT, 3});
    } else {
        texts.push_back({mk_rc.x + 14, mk_rc.y + 25, st.message.substr(0, 68),
                         st.phase == "error" ? COL_ROSE : COL_TEXT_SEC, 0});
    }

    // 4. Optional Frosted Glass POSIX File Browser Modal
    if (st.browser_open) {
        Rect mod{W / 6, H / 8, W * 2 / 3, H * 3 / 4};
        surf.draw_glass_card(mod, 20.0f, true, true);
        texts.push_back({mod.x + 22, mod.y + 30,
                         st.browser_for_dir ? "SELECT DIRECTORY" : "SELECT FILE OR DIRECTORY", COL_CYAN, 1});
        texts.push_back({mod.x + 22, mod.y + 54, st.browser_cwd, COL_TEXT_MONO, 3});

        st.rc_modal_list = {mod.x + 18, mod.y + 68, mod.w - 36, mod.h - 134};
        surf.draw_gradient_pill(st.rc_modal_list, 12.0f, COL_GLASS_INPUT, COL_GLASS_INPUT, 0.88f);
        int row_h = 28;
        int visible = st.rc_modal_list.h / row_h;
        for (int i = 0; i < visible && st.browser_scroll + i < static_cast<int>(st.browser_items.size()); ++i) {
            const auto &it = st.browser_items[st.browser_scroll + i];
            int y = st.rc_modal_list.y + i * row_h;
            std::string line = (it.is_dir ? "[DIR]  " : "[FILE] ") + it.name + (it.is_dir ? "/" : "   (" + fmt_bytes(it.size) + ")");
            texts.push_back({st.rc_modal_list.x + 14, y + 20, line.substr(0, 64),
                             it.is_dir ? COL_TEXT_MONO : COL_TEXT_PRI, 3});
        }
        st.rc_modal_select_dir = {mod.x + 20, mod.y + mod.h - 52, 180, 36};
        st.rc_modal_close      = {mod.x + mod.w - 120, mod.y + mod.h - 52, 100, 36};
        surf.draw_gradient_pill(st.rc_modal_select_dir, 10.0f, COL_CYAN, COL_ACCENT_END, 0.95f);
        surf.draw_gradient_pill(st.rc_modal_close, 10.0f, COL_GLASS_ELEV, COL_ROSE, 0.72f);
        texts.push_back({st.rc_modal_select_dir.x + 18, st.rc_modal_select_dir.y + 23, "USE THIS FOLDER", COL_VOID, 1});
        texts.push_back({st.rc_modal_close.x + 26, st.rc_modal_close.y + 23, "CLOSE", COL_TEXT_PRI, 1});
    }
}

int run_smoke_test(GuiState &st) {
    GlassSurface surf;
    surf.resize(1080, 720);
    std::vector<TextDraw> texts;
    st.tab = Tab::Audit;

    uint64_t j = openfir_selftest_start(on_engine_event, &st);
    if (j == 0) {
        std::fprintf(stderr, "[GUI SmokeTest] openfir_selftest_start failed\n");
        return 1;
    }
    {
        std::lock_guard<std::mutex> lk(st.mu);
        st.active_job = j;
    }

    bool done = false, ok = false;
    for (int step = 0; step < 300; ++step) {
        compose_scene(surf, st, step * 0.04f, texts);
        {
            std::lock_guard<std::mutex> lk(st.mu);
            if (st.phase == "done") { done = true; ok = true; }
            if (st.phase == "error") { done = true; ok = false; }
        }
        if (done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Verify rendered frosted-glass framebuffer contains vibrant non-void pixels
    size_t lit_pixels = 0;
    for (uint32_t p : surf.pixels) {
        if (((p >> 16) & 0xFF) > 30 || ((p >> 8) & 0xFF) > 40 || (p & 0xFF) > 55) ++lit_pixels;
    }
    std::printf("[GUI SmokeTest] version=%s phase=%s merkle=%.16s... lit_pixels=%zu/%zu texts=%zu\n",
                openfir_version(), st.phase.c_str(), st.merkle_hex.c_str(),
                lit_pixels, surf.pixels.size(), texts.size());
    return (ok && lit_pixels > 100000 && !st.merkle_hex.empty()) ? 0 : 2;
}

} // namespace

int main(int argc, char **argv) {
    GuiState st;
    do_keygen(st);

    if (argc > 1 && std::strcmp(argv[1], "--smoke-test") == 0) {
        return run_smoke_test(st);
    }

    Display *dpy = XOpenDisplay(nullptr);
    if (!dpy) {
        std::fprintf(stderr, "openfir-gui: cannot open X11 DISPLAY (use openfir-tui in SSH/headless or --smoke-test)\n");
        return 1;
    }

    int screen = DefaultScreen(dpy);
    Visual *vis = DefaultVisual(dpy, screen);
    Colormap cmap = DefaultColormap(dpy, screen);
    int depth = DefaultDepth(dpy, screen);

    int win_w = 1080, win_h = 700;
    Window win = XCreateSimpleWindow(dpy, RootWindow(dpy, screen), 120, 80, win_w, win_h, 0, 0, 0x070913);
    XStoreName(dpy, win, "OpenFIR v1.1 — Obsidian Frost Hybrid Transport");
    Atom wm_delete = XInternAtom(dpy, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(dpy, win, &wm_delete, 1);
    XSelectInput(dpy, win, ExposureMask | StructureNotifyMask | KeyPressMask | ButtonPressMask);
    XMapWindow(dpy, win);

    GC gc = XCreateGC(dpy, win, 0, nullptr);
    XftFont *fonts[4];
    fonts[0] = XftFontOpenName(dpy, screen, "sans-10");
    fonts[1] = XftFontOpenName(dpy, screen, "sans-10:bold");
    fonts[2] = XftFontOpenName(dpy, screen, "sans-14:bold");
    fonts[3] = XftFontOpenName(dpy, screen, "monospace-10");

    GlassSurface surf;
    surf.resize(win_w, win_h);
    Pixmap backbuf = XCreatePixmap(dpy, win, win_w, win_h, depth);
    XftDraw *xft_draw = XftDrawCreate(dpy, backbuf, vis, cmap);
    std::vector<TextDraw> texts;

    auto t0 = std::chrono::steady_clock::now();
    bool running = true;

    while (running) {
        while (XPending(dpy) > 0) {
            XEvent ev;
            XNextEvent(dpy, &ev);
            if (ev.type == ClientMessage && static_cast<Atom>(ev.xclient.data.l[0]) == wm_delete) {
                running = false;
            } else if (ev.type == ConfigureNotify) {
                if (ev.xconfigure.width != win_w || ev.xconfigure.height != win_h) {
                    win_w = std::max(900, ev.xconfigure.width);
                    win_h = std::max(640, ev.xconfigure.height);
                    surf.resize(win_w, win_h);
                    XftDrawDestroy(xft_draw);
                    XFreePixmap(dpy, backbuf);
                    backbuf = XCreatePixmap(dpy, win, win_w, win_h, depth);
                    xft_draw = XftDrawCreate(dpy, backbuf, vis, cmap);
                }
            } else if (ev.type == ButtonPress && ev.xbutton.button == Button1) {
                int mx = ev.xbutton.x, my = ev.xbutton.y;
                if (st.browser_open) {
                    if (st.rc_modal_close.contains(mx, my)) {
                        st.browser_open = false;
                    } else if (st.rc_modal_select_dir.contains(mx, my)) {
                        if (st.browser_for_dir) st.out_dir = st.browser_cwd;
                        else st.file_path = st.browser_cwd;
                        st.browser_open = false;
                    } else if (st.rc_modal_list.contains(mx, my)) {
                        int idx = st.browser_scroll + (my - st.rc_modal_list.y) / 28;
                        if (idx >= 0 && idx < static_cast<int>(st.browser_items.size())) {
                            const auto &it = st.browser_items[idx];
                            if (it.name == "..") {
                                auto pos = st.browser_cwd.find_last_of('/');
                                st.browser_cwd = (pos != std::string::npos && pos > 0) ? st.browser_cwd.substr(0, pos) : "/";
                                load_browser(st, st.browser_cwd);
                            } else if (it.is_dir) {
                                st.browser_cwd = (st.browser_cwd == "/" ? "/" : st.browser_cwd + "/") + it.name;
                                load_browser(st, st.browser_cwd);
                            } else if (!st.browser_for_dir) {
                                st.file_path = (st.browser_cwd == "/" ? "/" : st.browser_cwd + "/") + it.name;
                                st.browser_open = false;
                            }
                        }
                    }
                    continue;
                }
                for (int i = 0; i < 4; ++i) {
                    if (st.rc_tabs[i].contains(mx, my)) { st.tab = static_cast<Tab>(i); st.focus_field = 0; }
                    if (st.rc_fields[i].contains(mx, my)) st.focus_field = i;
                }
                if (st.rc_keygen.contains(mx, my)) do_keygen(st);
                if (st.rc_browse.contains(mx, my)) {
                    char cwd[512];
                    st.browser_cwd = getcwd(cwd, sizeof(cwd)) ? cwd : ".";
                    st.browser_for_dir = (st.tab == Tab::Server || st.tab == Tab::Pull);
                    load_browser(st, st.browser_cwd);
                    st.browser_open = true;
                }
                for (int i = 0; i < 3; ++i) {
                    if (st.rc_modes[i].contains(mx, my)) st.transport_idx = i;
                }
                if (st.rc_overwrite.contains(mx, my)) st.overwrite = !st.overwrite;
                if (st.rc_cta.contains(mx, my)) trigger_cta(st);
            } else if (ev.type == ButtonPress && st.browser_open && (ev.xbutton.button == 4 || ev.xbutton.button == 5)) {
                if (ev.xbutton.button == 4 && st.browser_scroll > 0) st.browser_scroll--;
                if (ev.xbutton.button == 5 && st.browser_scroll + 5 < static_cast<int>(st.browser_items.size())) st.browser_scroll++;
            } else if (ev.type == KeyPress) {
                KeySym ks = NoSymbol;
                char ch[16]{};
                int len = XLookupString(&ev.xkey, ch, sizeof(ch) - 1, &ks, nullptr);
                if (ks == XK_Escape) {
                    if (st.browser_open) st.browser_open = false;
                } else if (ks == XK_Tab) {
                    st.focus_field = (st.focus_field + 1) % 4;
                } else if (ks == XK_F5) {
                    trigger_cta(st);
                } else {
                    std::lock_guard<std::mutex> lk(st.mu);
                    std::string *fld = nullptr;
                    if (st.tab == Tab::Server) {
                        if (st.focus_field == 0) fld = &st.listen_addr;
                        else if (st.focus_field == 1) fld = &st.out_dir;
                        else if (st.focus_field == 2) fld = &st.secret;
                    } else if (st.tab == Tab::Push || st.tab == Tab::Pull) {
                        if (st.focus_field == 0) fld = &st.server_addr;
                        else if (st.focus_field == 1) fld = &st.secret;
                        else if (st.focus_field == 2) fld = &st.file_path;
                        else if (st.focus_field == 3 && st.tab == Tab::Pull) fld = &st.out_dir;
                    }
                    if (fld) {
                        if (ks == XK_BackSpace && !fld->empty()) fld->pop_back();
                        else if (len == 1 && static_cast<unsigned char>(ch[0]) >= 0x20 && static_cast<unsigned char>(ch[0]) < 0x7f) {
                            fld->push_back(ch[0]);
                        }
                    }
                }
            }
        }

        float elapsed = std::chrono::duration<float>(std::chrono::steady_clock::now() - t0).count();
        compose_scene(surf, st, elapsed, texts);

        XImage *img = XCreateImage(dpy, vis, depth, ZPixmap, 0,
                                   reinterpret_cast<char *>(surf.pixels.data()),
                                   win_w, win_h, 32, win_w * 4);
        if (img) {
            XPutImage(dpy, backbuf, gc, img, 0, 0, 0, 0, win_w, win_h);
            img->data = nullptr; // Owned by surf.pixels vector
            XDestroyImage(img);
        }

        for (const auto &td : texts) {
            XftFont *f = fonts[std::clamp(td.font_idx, 0, 3)];
            if (!f) continue;
            XRenderColor rc{
                static_cast<unsigned short>(td.col.r * 257u),
                static_cast<unsigned short>(td.col.g * 257u),
                static_cast<unsigned short>(td.col.b * 257u),
                0xFFFF
            };
            XftColor xcol{};
            XftColorAllocValue(dpy, vis, cmap, &rc, &xcol);
            XftDrawStringUtf8(xft_draw, &xcol, f, td.x, td.y,
                              reinterpret_cast<const FcChar8 *>(td.text.c_str()),
                              static_cast<int>(td.text.size()));
            XftColorFree(dpy, vis, cmap, &xcol);
        }

        XCopyArea(dpy, backbuf, win, gc, 0, 0, win_w, win_h, 0, 0);
        XFlush(dpy);
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }

    if (st.active_job) openfir_transfer_cancel(st.active_job);
    if (st.server_handle) openfir_server_stop(st.server_handle);
    for (auto *f : fonts) if (f) XftFontClose(dpy, f);
    XftDrawDestroy(xft_draw);
    XFreePixmap(dpy, backbuf);
    XFreeGC(dpy, gc);
    XDestroyWindow(dpy, win);
    XCloseDisplay(dpy);
    return 0;
}
