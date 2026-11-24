/* SPDX-License-Identifier: Apache-2.0
 *
 * OpenFIR Linux CLI Pseudo-Graphical Frosted-Glass TUI (openfir-tui)
 * Pure C11 — ZERO third-party libraries (no ncurses, no termbox, no external deps).
 * Uses raw POSIX termios, ioctl(TIOCGWINSZ), SGR 1006 mouse tracking, DEC 2026 sync
 * frames, 24-bit TrueColor spatial-blur alpha-blended frosted glass cards over live
 * animated Web3 aurora plasma, and 2x4 sub-pixel Unicode Braille sparklines.
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "openfir.h"

/* ============================================================================
 * Obsidian Frost x Neon Aurora Canonical Palette
 * ============================================================================ */
typedef struct { uint8_t r, g, b; } RGB;

static const RGB COL_BG_VOID      = {  7,   9,  19};
static const RGB COL_AURORA_CYAN  = {  0, 240, 255};
static const RGB COL_AURORA_VIO   = {139,  92, 246};
static const RGB COL_AURORA_MAG   = {236,  72, 153};
static const RGB COL_GLASS_TINT   = { 17,  23,  42};
static const RGB COL_GLASS_ELEV   = { 26,  35,  62};
static const RGB COL_GLASS_INPUT  = { 10,  15,  29};
static const RGB COL_ACCENT_END   = {124,  58, 237};
static const RGB COL_MINT         = { 16, 249, 160};
static const RGB COL_AMBER        = {255, 176,  32};
static const RGB COL_ROSE         = {255,  77, 141};
static const RGB COL_TEXT_PRI     = {248, 250, 252};
static const RGB COL_TEXT_SEC     = {148, 163, 184};
static const RGB COL_TEXT_MUTED   = {100, 116, 139};
static const RGB COL_TEXT_MONO    = {125, 211, 252};

static inline uint8_t clamp_u8(double v) {
    if (v < 0.0) return 0;
    if (v > 255.0) return 255;
    return (uint8_t)(v + 0.5);
}

static inline RGB rgb_lerp(RGB a, RGB b, double t) {
    if (t < 0.0) t = 0.0;
    if (t > 1.0) t = 1.0;
    return (RGB){
        clamp_u8(a.r + (b.r - a.r) * t),
        clamp_u8(a.g + (b.g - a.g) * t),
        clamp_u8(a.b + (b.b - a.b) * t)
    };
}

static inline RGB rgb_add(RGB base, RGB glow, double strength) {
    return (RGB){
        clamp_u8(base.r + glow.r * strength),
        clamp_u8(base.g + glow.g * strength),
        clamp_u8(base.b + glow.b * strength)
    };
}

/* ============================================================================
 * Double-Buffered 24-Bit TrueColor Terminal Cell Compositor
 * ============================================================================ */
typedef struct {
    char glyph[8];
    RGB fg;
    RGB bg;
    uint8_t bold;
} Cell;

typedef struct {
    int w, h;
    Cell *front;
    Cell *back;
    RGB  *plasma; /* Underlying animated aurora field for real spatial glass blur */
    char *out_buf;
    size_t out_cap;
    size_t out_len;
    bool force_full;
} Canvas;

static void canvas_init(Canvas *c) {
    memset(c, 0, sizeof(*c));
    c->out_cap = 262144;
    c->out_buf = (char *)malloc(c->out_cap);
    c->force_full = true;
}

static void canvas_free(Canvas *c) {
    free(c->front);
    free(c->back);
    free(c->plasma);
    free(c->out_buf);
    memset(c, 0, sizeof(*c));
}

static void canvas_resize(Canvas *c, int w, int h) {
    if (w < 60) w = 60;
    if (h < 22) h = 22;
    if (w == c->w && h == c->h && c->back && c->front && c->plasma) return;
    free(c->front);
    free(c->back);
    free(c->plasma);
    size_t n = (size_t)w * (size_t)h;
    c->front  = (Cell *)calloc(n, sizeof(Cell));
    c->back   = (Cell *)calloc(n, sizeof(Cell));
    c->plasma = (RGB  *)calloc(n, sizeof(RGB));
    c->w = w;
    c->h = h;
    c->force_full = true;
}

static void out_append(Canvas *c, const char *s, size_t n) {
    if (c->out_len + n + 64 >= c->out_cap) {
        size_t ncap = c->out_cap * 2 + n + 1024;
        char *nb = (char *)realloc(c->out_buf, ncap);
        if (!nb) return;
        c->out_buf = nb;
        c->out_cap = ncap;
    }
    memcpy(c->out_buf + c->out_len, s, n);
    c->out_len += n;
}

static void out_str(Canvas *c, const char *s) {
    out_append(c, s, strlen(s));
}

static void canvas_render_aurora(Canvas *c, double t) {
    /* Three smoothly orbiting radial plasma lights over #070913 obsidian void */
    double cx1 = 0.22 + 0.08 * sin(t * 0.45);
    double cy1 = 0.24 + 0.07 * cos(t * 0.38);
    double cx2 = 0.78 + 0.09 * cos(t * 0.35);
    double cy2 = 0.76 + 0.08 * sin(t * 0.42);
    double cx3 = 0.62 + 0.10 * sin(t * 0.28 + 1.4);
    double cy3 = 0.28 + 0.09 * cos(t * 0.31 + 0.8);

    double inv_w = 1.0 / (double)(c->w > 1 ? c->w - 1 : 1);
    double inv_h = 1.0 / (double)(c->h > 1 ? c->h - 1 : 1);

    for (int y = 0; y < c->h; y++) {
        double ny = (double)y * inv_h;
        for (int x = 0; x < c->w; x++) {
            double nx = (double)x * inv_w;
            double d1 = (nx - cx1) * (nx - cx1) * 1.4 + (ny - cy1) * (ny - cy1) * 2.2;
            double d2 = (nx - cx2) * (nx - cx2) * 1.3 + (ny - cy2) * (ny - cy2) * 2.0;
            double d3 = (nx - cx3) * (nx - cx3) * 1.8 + (ny - cy3) * (ny - cy3) * 2.6;

            double g1 = exp(-d1 * 5.2) * 0.30;
            double g2 = exp(-d2 * 4.8) * 0.32;
            double g3 = exp(-d3 * 6.5) * 0.16;

            RGB bg = COL_BG_VOID;
            bg = rgb_add(bg, COL_AURORA_CYAN, g1);
            bg = rgb_add(bg, COL_AURORA_VIO,  g2);
            bg = rgb_add(bg, COL_AURORA_MAG,  g3);

            int idx = y * c->w + x;
            c->plasma[idx] = bg;
            c->back[idx].glyph[0] = ' ';
            c->back[idx].glyph[1] = '\0';
            c->back[idx].bg = bg;
            c->back[idx].fg = COL_TEXT_PRI;
            c->back[idx].bold = 0;
        }
    }
}

/* Spatial 3x3 blurred aurora sample for authentic frosted-glass translucency */
static RGB sample_blurred_plasma(const Canvas *c, int x, int y) {
    int sr = 0, sg = 0, sb = 0, cnt = 0;
    for (int dy = -1; dy <= 1; dy++) {
        int yy = y + dy;
        if (yy < 0 || yy >= c->h) continue;
        for (int dx = -2; dx <= 2; dx++) {
            int xx = x + dx;
            if (xx < 0 || xx >= c->w) continue;
            RGB p = c->plasma[yy * c->w + xx];
            sr += p.r; sg += p.g; sb += p.b;
            cnt++;
        }
    }
    if (cnt == 0) return COL_BG_VOID;
    return (RGB){(uint8_t)(sr / cnt), (uint8_t)(sg / cnt), (uint8_t)(sb / cnt)};
}

static void put_cell(Canvas *c, int x, int y, const char *utf8, RGB fg, RGB bg, uint8_t bold) {
    if (x < 0 || x >= c->w || y < 0 || y >= c->h) return;
    Cell *cell = &c->back[y * c->w + x];
    size_t len = strlen(utf8);
    if (len >= sizeof(cell->glyph)) len = sizeof(cell->glyph) - 1;
    memcpy(cell->glyph, utf8, len);
    cell->glyph[len] = '\0';
    cell->fg = fg;
    cell->bg = bg;
    cell->bold = bold;
}

static void put_text(Canvas *c, int x, int y, int max_w, const char *s, RGB fg, uint8_t bold) {
    if (y < 0 || y >= c->h || !s || max_w <= 0) return;
    int col = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p && col < max_w && x + col < c->w) {
        size_t clen = 1;
        if ((*p & 0xE0) == 0xC0) clen = 2;
        else if ((*p & 0xF0) == 0xE0) clen = 3;
        else if ((*p & 0xF8) == 0xF0) clen = 4;
        char g[8] = {0};
        for (size_t i = 0; i < clen && p[i]; i++) g[i] = (char)p[i];
        int cx = x + col;
        if (cx >= 0 && cx < c->w) {
            RGB bg = c->back[y * c->w + cx].bg;
            put_cell(c, cx, y, g, fg, bg, bold);
        }
        p += clen;
        col++;
    }
}

/* Draw frosted glass panel: spatial blur + tint + specular cyan->violet rim */
static void draw_glass_card(Canvas *c, int x, int y, int w, int h, bool elevated, bool active_rim, const char *title) {
    if (w < 4 || h < 3) return;
    RGB tint = elevated ? COL_GLASS_ELEV : COL_GLASS_TINT;
    double alpha = elevated ? 0.74 : 0.62;

    for (int j = 0; j < h; j++) {
        int yy = y + j;
        if (yy < 0 || yy >= c->h) continue;
        for (int i = 0; i < w; i++) {
            int xx = x + i;
            if (xx < 0 || xx >= c->w) continue;
            RGB blurred = sample_blurred_plasma(c, xx, yy);
            RGB frosted = rgb_lerp(blurred, tint, alpha);
            /* Subtle top inner glass specular sheen */
            if (j == 1) frosted = rgb_add(frosted, (RGB){255, 255, 255}, 0.05);

            bool on_border = (i == 0 || i == w - 1 || j == 0 || j == h - 1);
            if (!on_border) {
                put_cell(c, xx, yy, " ", COL_TEXT_PRI, frosted, 0);
            } else {
                double grad = ((double)i / (double)(w - 1) + (double)j / (double)(h - 1)) * 0.5;
                RGB rim_start = active_rim ? COL_AURORA_CYAN : rgb_lerp(COL_AURORA_CYAN, COL_TEXT_PRI, 0.55);
                RGB rim_end   = active_rim ? COL_AURORA_VIO  : (RGB){82, 98, 132};
                RGB rim = rgb_lerp(rim_start, rim_end, grad);
                if (!active_rim) rim = rgb_lerp(frosted, rim, 0.52);

                const char *ch = "─";
                if (i == 0 && j == 0) ch = "╭";
                else if (i == w - 1 && j == 0) ch = "╮";
                else if (i == 0 && j == h - 1) ch = "╰";
                else if (i == w - 1 && j == h - 1) ch = "╯";
                else if (i == 0 || i == w - 1) ch = "│";
                put_cell(c, xx, yy, ch, rim, frosted, active_rim ? 1 : 0);
            }
        }
    }

    if (title && title[0] && w > 8) {
        char hdr[96];
        snprintf(hdr, sizeof(hdr), " %s ", title);
        put_text(c, x + 2, y, w - 4, hdr, active_rim ? COL_AURORA_CYAN : COL_TEXT_PRI, 1);
    }
}

static void draw_pill(Canvas *c, int x, int y, int w, const char *label, bool active, RGB accent_a, RGB accent_b) {
    if (y < 0 || y >= c->h || w < 3) return;
    for (int i = 0; i < w; i++) {
        int xx = x + i;
        if (xx < 0 || xx >= c->w) continue;
        double t = w > 1 ? (double)i / (double)(w - 1) : 0.0;
        RGB bg = active ? rgb_lerp(accent_a, accent_b, t)
                        : rgb_lerp(sample_blurred_plasma(c, xx, y), COL_GLASS_ELEV, 0.72);
        put_cell(c, xx, y, " ", active ? COL_BG_VOID : COL_TEXT_SEC, bg, active ? 1 : 0);
    }
    int len = (int)strlen(label);
    int tx = x + (w - len) / 2;
    if (tx < x + 1) tx = x + 1;
    put_text(c, tx, y, w - 2, label, active ? COL_BG_VOID : COL_TEXT_SEC, active ? 1 : 0);
}

static void draw_progress_bar(Canvas *c, int x, int y, int w, double pct) {
    static const char *blocks[8] = {" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"};
    if (w <= 2 || y < 0 || y >= c->h) return;
    if (pct < 0.0) pct = 0.0;
    if (pct > 100.0) pct = 100.0;
    double filled = (pct / 100.0) * (double)w;
    int full_cells = (int)filled;
    int frac = (int)((filled - full_cells) * 8.0);

    for (int i = 0; i < w; i++) {
        int xx = x + i;
        if (xx < 0 || xx >= c->w) continue;
        double t = w > 1 ? (double)i / (double)(w - 1) : 0.0;
        RGB grad = rgb_lerp(COL_AURORA_CYAN, COL_ACCENT_END, t);
        RGB track = rgb_lerp(sample_blurred_plasma(c, xx, y), COL_GLASS_INPUT, 0.80);
        if (i < full_cells) {
            put_cell(c, xx, y, "█", grad, track, 0);
        } else if (i == full_cells && frac > 0) {
            put_cell(c, xx, y, blocks[frac], grad, track, 0);
        } else {
            put_cell(c, xx, y, "░", COL_TEXT_MUTED, track, 0);
        }
    }
}

/* 2x4 sub-pixel Unicode Braille neon throughput sparkline */
static void draw_braille_sparkline(Canvas *c, int x, int y, int w, int h, const double *samples, int count) {
    if (w < 4 || h < 2 || count <= 0) return;
    double max_v = 1.0;
    for (int i = 0; i < count; i++) {
        if (samples[i] > max_v) max_v = samples[i];
    }

    int pw = w * 2;
    int ph = h * 4;
    uint8_t *dots = (uint8_t *)calloc((size_t)(w * h), 1);
    if (!dots) return;

    static const uint8_t bit_l[4] = {0x01, 0x02, 0x04, 0x40};
    static const uint8_t bit_r[4] = {0x08, 0x10, 0x20, 0x80};

    for (int px = 0; px < pw; px++) {
        int si = (px * count) / pw;
        if (si >= count) si = count - 1;
        double norm = samples[si] / max_v;
        if (norm < 0.0) norm = 0.0;
        if (norm > 1.0) norm = 1.0;
        int top_py = ph - 1 - (int)(norm * (ph - 1) + 0.5);
        for (int py = top_py; py < ph; py++) {
            int cx = px / 2;
            int cy = py / 4;
            int sub_x = px % 2;
            int sub_y = py % 4;
            dots[cy * w + cx] |= (sub_x == 0 ? bit_l[sub_y] : bit_r[sub_y]);
        }
    }

    for (int cy = 0; cy < h; cy++) {
        int yy = y + cy;
        if (yy < 0 || yy >= c->h) continue;
        double v_ratio = h > 1 ? (double)cy / (double)(h - 1) : 0.0;
        RGB fg = rgb_lerp(COL_AURORA_CYAN, COL_AURORA_VIO, v_ratio);
        for (int cx = 0; cx < w; cx++) {
            int xx = x + cx;
            if (xx < 0 || xx >= c->w) continue;
            uint32_t cp = 0x2800u | (uint32_t)dots[cy * w + cx];
            char utf8[4];
            utf8[0] = (char)(0xE0 | ((cp >> 12) & 0x0F));
            utf8[1] = (char)(0x80 | ((cp >> 6)  & 0x3F));
            utf8[2] = (char)(0x80 | (cp & 0x3F));
            utf8[3] = '\0';
            RGB bg = c->back[yy * c->w + xx].bg;
            put_cell(c, xx, yy, utf8, dots[cy * w + cx] ? fg : COL_TEXT_MUTED, bg, 0);
        }
    }
    free(dots);
}

static void canvas_flush(Canvas *c, int fd) {
    c->out_len = 0;
    out_str(c, "\x1b[?2026h\x1b[?25l");
    RGB cur_fg = {255, 255, 255}, cur_bg = {0, 0, 0};
    uint8_t cur_bold = 255;
    bool has_style = false;
    int last_x = -10, last_y = -10;

    for (int y = 0; y < c->h; y++) {
        for (int x = 0; x < c->w; x++) {
            int idx = y * c->w + x;
            Cell *b = &c->back[idx];
            Cell *f = &c->front[idx];
            if (!c->force_full &&
                b->fg.r == f->fg.r && b->fg.g == f->fg.g && b->fg.b == f->fg.b &&
                b->bg.r == f->bg.r && b->bg.g == f->bg.g && b->bg.b == f->bg.b &&
                b->bold == f->bold && strcmp(b->glyph, f->glyph) == 0) {
                continue;
            }
            if (y != last_y || x != last_x + 1) {
                char pos[32];
                int pn = snprintf(pos, sizeof(pos), "\x1b[%d;%dH", y + 1, x + 1);
                out_append(c, pos, (size_t)pn);
            }
            if (!has_style || b->bold != cur_bold ||
                b->fg.r != cur_fg.r || b->fg.g != cur_fg.g || b->fg.b != cur_fg.b ||
                b->bg.r != cur_bg.r || b->bg.g != cur_bg.g || b->bg.b != cur_bg.b) {
                char sty[64];
                int sn = snprintf(sty, sizeof(sty), "\x1b[%d;38;2;%u;%u;%u;48;2;%u;%u;%um",
                                  b->bold ? 1 : 22,
                                  b->fg.r, b->fg.g, b->fg.b,
                                  b->bg.r, b->bg.g, b->bg.b);
                out_append(c, sty, (size_t)sn);
                cur_fg = b->fg;
                cur_bg = b->bg;
                cur_bold = b->bold;
                has_style = true;
            }
            out_str(c, b->glyph[0] ? b->glyph : " ");
            *f = *b;
            last_x = x;
            last_y = y;
        }
    }
    out_str(c, "\x1b[0m\x1b[?2026l");
    c->force_full = false;

    if (fd >= 0 && c->out_len > 0) {
        size_t off = 0;
        while (off < c->out_len) {
            ssize_t wr = write(fd, c->out_buf + off, c->out_len - off);
            if (wr <= 0) break;
            off += (size_t)wr;
        }
    }
}

/* ============================================================================
 * Minimal Zero-Dep JSON Telemetry Extractor (Reads ProgressSnapshot JSON)
 * ============================================================================ */
static bool json_extract_str(const char *json, const char *key, char *out, size_t cap) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) return false;
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return true;
}

static double json_extract_num(const char *json, const char *key, double def) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return def;
    p += strlen(pat);
    while (*p == ' ') p++;
    char *end = NULL;
    double v = strtod(p, &end);
    return (end != p) ? v : def;
}

static void json_escape(const char *src, char *dst, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; src && src[i] && j + 2 < cap; i++) {
        char ch = src[i];
        if (ch == '"' || ch == '\\') {
            dst[j++] = '\\';
            dst[j++] = ch;
        } else if ((unsigned char)ch >= 0x20) {
            dst[j++] = ch;
        }
    }
    dst[j] = '\0';
}

/* ============================================================================
 * Application State + Engine Bridge
 * ============================================================================ */
typedef enum { TAB_PUSH = 0, TAB_PULL = 1, TAB_SERVER = 2, TAB_AUDIT = 3 } TabID;

typedef struct {
    char name[256];
    bool is_dir;
    off_t size;
} DirItem;

typedef struct {
    pthread_mutex_t mu;
    TabID tab;
    int focus_idx;
    bool editing;

    /* Form fields */
    char server_addr[128];
    char secret[128];
    char file_path[512];
    char out_dir[512];
    char listen_addr[128];
    int transport_idx; /* 0=auto, 1=udp, 2=tcp */
    int tcp_streams;
    int max_mbps;
    bool overwrite;

    /* Active handles */
    uint64_t active_job;
    uint64_t server_handle;
    char server_status[192];

    /* Live telemetry */
    char phase[32];
    char message[256];
    char active_lane[32];
    char merkle_hex[96];
    double percent;
    double goodput_mbps;
    double instant_mbps;
    double rtt_ms;
    int64_t bytes_done;
    int64_t total_bytes;
    uint64_t wire_udp;
    uint64_t wire_tcp;
    uint32_t total_blocks;
    uint32_t cas_blocks;
    uint32_t zero_blocks;
    uint32_t comp_blocks;
    uint64_t fec_parity;
    uint32_t fec_recovered;
    uint32_t failover_blocks;
    int suite_idx;
    int suite_total;
    double spark[60];

    /* Modal POSIX File Browser */
    bool browser_open;
    bool browser_for_dir;
    char browser_cwd[512];
    DirItem *items;
    int item_count;
    int browser_sel;
} AppState;

static void app_push_spark(AppState *st, double mbps) {
    memmove(&st->spark[0], &st->spark[1], sizeof(st->spark) - sizeof(st->spark[0]));
    st->spark[59] = mbps > 0.0 ? mbps : 0.0;
}

static void on_openfir_event(uint64_t handle, const char *json, void *ctx) {
    AppState *st = (AppState *)ctx;
    if (!st || !json) return;

    char op[32] = {0}, phase[32] = {0}, msg[256] = {0}, lane[32] = {0}, merkle[96] = {0};
    json_extract_str(json, "op", op, sizeof(op));
    json_extract_str(json, "phase", phase, sizeof(phase));
    json_extract_str(json, "message", msg, sizeof(msg));
    json_extract_str(json, "active_lane", lane, sizeof(lane));
    json_extract_str(json, "merkle_root_hex", merkle, sizeof(merkle));

    pthread_mutex_lock(&st->mu);
    if (strcmp(op, "server") == 0) {
        if (strcmp(phase, "listening") == 0) {
            snprintf(st->server_status, sizeof(st->server_status), "%s", msg);
            snprintf(st->phase, sizeof(st->phase), "listening");
            snprintf(st->message, sizeof(st->message), "%s", msg);
        } else if (strcmp(phase, "error") == 0) {
            st->server_handle = 0;
            snprintf(st->server_status, sizeof(st->server_status), "ERROR: %s", msg);
            snprintf(st->phase, sizeof(st->phase), "error");
            snprintf(st->message, sizeof(st->message), "%s", msg);
        }
        pthread_mutex_unlock(&st->mu);
        return;
    }

    if (handle != 0 && st->active_job != 0 && handle != st->active_job) {
        pthread_mutex_unlock(&st->mu);
        return;
    }

    if (phase[0]) snprintf(st->phase, sizeof(st->phase), "%s", phase);
    if (msg[0])   snprintf(st->message, sizeof(st->message), "%s", msg);
    if (lane[0])  snprintf(st->active_lane, sizeof(st->active_lane), "%s", lane);
    if (merkle[0]) snprintf(st->merkle_hex, sizeof(st->merkle_hex), "%s", merkle);

    st->percent         = json_extract_num(json, "percent", st->percent);
    st->goodput_mbps    = json_extract_num(json, "goodput_mbps", st->goodput_mbps);
    st->instant_mbps    = json_extract_num(json, "instant_mbps", st->instant_mbps);
    st->rtt_ms          = json_extract_num(json, "rtt_ms", st->rtt_ms);
    st->bytes_done      = (int64_t)json_extract_num(json, "bytes_done", (double)st->bytes_done);
    st->total_bytes     = (int64_t)json_extract_num(json, "total_bytes", (double)st->total_bytes);
    st->wire_udp        = (uint64_t)json_extract_num(json, "wire_udp_bytes", (double)st->wire_udp);
    st->wire_tcp        = (uint64_t)json_extract_num(json, "wire_tcp_bytes", (double)st->wire_tcp);
    st->total_blocks    = (uint32_t)json_extract_num(json, "total_blocks", (double)st->total_blocks);
    st->cas_blocks      = (uint32_t)json_extract_num(json, "cas_blocks", (double)st->cas_blocks);
    st->zero_blocks     = (uint32_t)json_extract_num(json, "zero_blocks", (double)st->zero_blocks);
    st->comp_blocks     = (uint32_t)json_extract_num(json, "compressed_blocks", (double)st->comp_blocks);
    st->fec_parity      = (uint64_t)json_extract_num(json, "fec_parity_sent", (double)st->fec_parity);
    st->fec_recovered   = (uint32_t)json_extract_num(json, "fec_recovered", (double)st->fec_recovered);
    st->failover_blocks = (uint32_t)json_extract_num(json, "udp_fallback_blocks", (double)st->failover_blocks);
    st->suite_idx       = (int)json_extract_num(json, "suite_index", (double)st->suite_idx);
    st->suite_total     = (int)json_extract_num(json, "suite_total", (double)st->suite_total);

    double plot_v = st->instant_mbps > 0.01 ? st->instant_mbps : st->goodput_mbps;
    if (strcmp(phase, "transferring") == 0 || strcmp(phase, "done") == 0) {
        app_push_spark(st, plot_v);
    }
    if (strcmp(phase, "done") == 0 || strcmp(phase, "error") == 0) {
        st->active_job = 0;
    }
    pthread_mutex_unlock(&st->mu);
}

/* ============================================================================
 * POSIX File/Directory Browser Modal (Zero Third-Party Deps)
 * ============================================================================ */
static int cmp_dir_item(const void *a, const void *b) {
    const DirItem *da = (const DirItem *)a;
    const DirItem *db = (const DirItem *)b;
    if (strcmp(da->name, "..") == 0) return -1;
    if (strcmp(db->name, "..") == 0) return 1;
    if (da->is_dir != db->is_dir) return da->is_dir ? -1 : 1;
    return strcmp(da->name, db->name);
}

static void browser_load(AppState *st, const char *dir) {
    DIR *dp = opendir(dir);
    if (!dp) return;
    free(st->items);
    st->items = NULL;
    st->item_count = 0;
    int cap = 64;
    st->items = (DirItem *)calloc((size_t)cap, sizeof(DirItem));
    if (!st->items) { closedir(dp); return; }

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0) continue;
        if (st->item_count >= cap) {
            cap *= 2;
            DirItem *ni = (DirItem *)realloc(st->items, (size_t)cap * sizeof(DirItem));
            if (!ni) break;
            st->items = ni;
        }
        DirItem *it = &st->items[st->item_count++];
        snprintf(it->name, sizeof(it->name), "%s", de->d_name);
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
        struct stat sb;
        if (stat(full, &sb) == 0) {
            it->is_dir = S_ISDIR(sb.st_mode);
            it->size = sb.st_size;
        } else {
            it->is_dir = false;
            it->size = 0;
        }
    }
    closedir(dp);
    qsort(st->items, (size_t)st->item_count, sizeof(DirItem), cmp_dir_item);
    st->browser_sel = 0;
}

static void format_bytes(int64_t b, char *out, size_t cap) {
    if (b >= 1024LL * 1024 * 1024) snprintf(out, cap, "%.2f GiB", (double)b / (1024.0 * 1024.0 * 1024.0));
    else if (b >= 1024LL * 1024)   snprintf(out, cap, "%.2f MiB", (double)b / (1024.0 * 1024.0));
    else if (b >= 1024LL)          snprintf(out, cap, "%.1f KiB", (double)b / 1024.0);
    else                           snprintf(out, cap, "%lld B", (long long)b);
}

/* ============================================================================
 * Action Triggers
 * ============================================================================ */
static void trigger_keygen(AppState *st) {
    char buf[80] = {0};
    if (openfir_keygen(buf, sizeof(buf)) == 64) {
        pthread_mutex_lock(&st->mu);
        snprintf(st->secret, sizeof(st->secret), "%s", buf);
        snprintf(st->message, sizeof(st->message), "Generated fresh 256-bit cryptographically secure key");
        pthread_mutex_unlock(&st->mu);
    }
}

static void trigger_primary_action(AppState *st) {
    pthread_mutex_lock(&st->mu);
    TabID tab = st->tab;

    if (tab == TAB_SERVER) {
        if (st->server_handle != 0) {
            uint64_t h = st->server_handle;
            st->server_handle = 0;
            snprintf(st->server_status, sizeof(st->server_status), "Server stopped");
            snprintf(st->phase, sizeof(st->phase), "idle");
            snprintf(st->message, sizeof(st->message), "Dual-stack server stopped cleanly");
            pthread_mutex_unlock(&st->mu);
            openfir_server_stop(h);
            return;
        }
        char e_listen[256], e_dir[1024], e_sec[256];
        json_escape(st->listen_addr, e_listen, sizeof(e_listen));
        json_escape(st->out_dir, e_dir, sizeof(e_dir));
        json_escape(st->secret, e_sec, sizeof(e_sec));
        char cfg[2048];
        snprintf(cfg, sizeof(cfg),
                 "{\"listen\":\"%s\",\"dir\":\"%s\",\"secret\":\"%s\",\"overwrite\":%s,\"max_sessions\":64}",
                 e_listen, e_dir, e_sec, st->overwrite ? "true" : "false");
        pthread_mutex_unlock(&st->mu);
        uint64_t h = openfir_server_start(cfg, on_openfir_event, st);
        pthread_mutex_lock(&st->mu);
        st->server_handle = h;
        pthread_mutex_unlock(&st->mu);
        return;
    }

    if (st->active_job != 0) {
        uint64_t j = st->active_job;
        st->active_job = 0;
        snprintf(st->phase, sizeof(st->phase), "idle");
        snprintf(st->message, sizeof(st->message), "Cancellation requested...");
        pthread_mutex_unlock(&st->mu);
        openfir_transfer_cancel(j);
        return;
    }

    /* Reset telemetry for new transfer or audit */
    st->percent = 0.0;
    st->goodput_mbps = 0.0;
    st->instant_mbps = 0.0;
    st->bytes_done = 0;
    st->total_bytes = 0;
    st->wire_udp = 0;
    st->wire_tcp = 0;
    st->cas_blocks = 0;
    st->zero_blocks = 0;
    st->comp_blocks = 0;
    st->fec_parity = 0;
    st->fec_recovered = 0;
    st->failover_blocks = 0;
    st->merkle_hex[0] = '\0';
    memset(st->spark, 0, sizeof(st->spark));

    if (tab == TAB_AUDIT) {
        snprintf(st->phase, sizeof(st->phase), "transferring");
        snprintf(st->message, sizeof(st->message), "Starting 4-Suite Enterprise Protocol Audit...");
        pthread_mutex_unlock(&st->mu);
        uint64_t j = openfir_selftest_start(on_openfir_event, st);
        pthread_mutex_lock(&st->mu);
        st->active_job = j;
        pthread_mutex_unlock(&st->mu);
        return;
    }

    static const char *modes[3] = {"auto", "udp", "tcp"};
    char e_srv[256], e_sec[256], e_file[1024], e_dir[1024];
    json_escape(st->server_addr, e_srv, sizeof(e_srv));
    json_escape(st->secret, e_sec, sizeof(e_sec));
    json_escape(st->file_path, e_file, sizeof(e_file));
    json_escape(st->out_dir, e_dir, sizeof(e_dir));

    char cfg[3072];
    snprintf(cfg, sizeof(cfg),
             "{\"op\":\"%s\",\"server\":\"%s\",\"secret\":\"%s\",\"file\":\"%s\","
             "\"dir\":\"%s\",\"transport\":\"%s\",\"tcp_streams\":%d,\"max_mbps\":%d,\"overwrite\":%s}",
             tab == TAB_PUSH ? "push" : "pull",
             e_srv, e_sec, e_file, e_dir,
             modes[st->transport_idx % 3],
             st->tcp_streams, st->max_mbps,
             st->overwrite ? "true" : "false");
    snprintf(st->phase, sizeof(st->phase), "handshake");
    pthread_mutex_unlock(&st->mu);

    uint64_t j = openfir_transfer_start(cfg, on_openfir_event, st);
    pthread_mutex_lock(&st->mu);
    if (j != 0) st->active_job = j;
    pthread_mutex_unlock(&st->mu);
}

/* ============================================================================
 * Unified Obsidian Frost x Neon Aurora Frame Rendering
 * ============================================================================ */
static void draw_field_row(Canvas *c, int x, int y, int w, const char *label, const char *val, bool focused, bool editing) {
    put_text(c, x, y, w, label, focused ? COL_AURORA_CYAN : COL_TEXT_SEC, focused ? 1 : 0);
    int iy = y + 1;
    if (iy >= c->h) return;
    for (int i = 0; i < w; i++) {
        int xx = x + i;
        if (xx < 0 || xx >= c->w) continue;
        RGB bg = rgb_lerp(sample_blurred_plasma(c, xx, iy), COL_GLASS_INPUT, focused ? 0.86 : 0.72);
        put_cell(c, xx, iy, " ", COL_TEXT_MONO, bg, 0);
    }
    RGB edge = editing ? COL_MINT : (focused ? COL_AURORA_CYAN : COL_TEXT_MUTED);
    put_cell(c, x, iy, "▎", edge, c->back[iy * c->w + x].bg, 1);
    char disp[512];
    if (editing) snprintf(disp, sizeof(disp), "%s▌", val);
    else snprintf(disp, sizeof(disp), "%s", val[0] ? val : "(empty)");
    put_text(c, x + 2, iy, w - 3, disp, val[0] || editing ? COL_TEXT_MONO : COL_TEXT_MUTED, 0);
}

static void render_ui(Canvas *c, AppState *st, double t) {
    canvas_render_aurora(c, t);

    pthread_mutex_lock(&st->mu);
    int W = c->w, H = c->h;

    /* 1. Top Frosted Header Strip */
    draw_glass_card(c, 1, 0, W - 2, 3, true, true, NULL);
    put_text(c, 3, 1, 24, "◆ OPENFIR", COL_AURORA_CYAN, 1);
    put_text(c, 13, 1, 10, "v2.0 FROST", COL_AURORA_VIO, 1);

    /* 4 Frosted Mode Tabs */
    const char *tab_names[4] = {"1 PUSH", "2 PULL", "3 SERVER", "4 AUDIT"};
    int tx = 26;
    for (int i = 0; i < 4; i++) {
        draw_pill(c, tx, 1, 11, tab_names[i], st->tab == (TabID)i, COL_AURORA_CYAN, COL_ACCENT_END);
        tx += 12;
    }

    /* Live Status Badge on Right */
    RGB st_col = COL_TEXT_SEC;
    const char *st_lbl = "● IDLE";
    if (strcmp(st->phase, "done") == 0)           { st_col = COL_MINT;        st_lbl = "✓ MERKLE VERIFIED"; }
    else if (strcmp(st->phase, "listening") == 0) { st_col = COL_MINT;        st_lbl = "◉ SERVER LIVE"; }
    else if (strcmp(st->phase, "transferring") == 0 || strcmp(st->phase, "handshake") == 0) {
        st_col = COL_AURORA_CYAN; st_lbl = "◈ ACTIVE STREAM";
    } else if (strcmp(st->phase, "error") == 0)   { st_col = COL_ROSE;        st_lbl = "✕ ERROR"; }
    if (W > 78) {
        put_text(c, W - 21, 1, 19, st_lbl, st_col, 1);
    }

    /* 2. Split Main Frosted Workspace */
    int body_y = 3;
    int body_h = H - 5;
    int left_w = (W - 3) * 46 / 100;
    if (left_w < 34) left_w = 34;
    int right_x = left_w + 2;
    int right_w = W - right_x - 1;

    /* Left Frosted Control Card */
    const char *card_title = st->tab == TAB_PUSH ? "PUSH · HYBRID UPLOAD" :
                             st->tab == TAB_PULL ? "PULL · MERKLE DOWNLOAD" :
                             st->tab == TAB_SERVER ? "SERVER · DUAL-STACK TLS1.3+UDP" :
                             "AUDIT · 4-SUITE PROTOCOL VERIFICATION";
    draw_glass_card(c, 1, body_y, left_w, body_h, false, true, card_title);

    int fx = 3, fw = left_w - 4, fy = body_y + 2;
    if (st->tab == TAB_PUSH || st->tab == TAB_PULL) {
        draw_field_row(c, fx, fy, fw, "SERVER ENDPOINT (host:port)", st->server_addr, st->focus_idx == 0, st->editing && st->focus_idx == 0);
        fy += 3;
        draw_field_row(c, fx, fy, fw, "256-BIT SHARED SECRET  [K=Keygen]", st->secret, st->focus_idx == 1, st->editing && st->focus_idx == 1);
        fy += 3;
        draw_field_row(c, fx, fy, fw,
                       st->tab == TAB_PUSH ? "LOCAL FILE / DIR  [B=Browse]" : "REMOTE FILE / DIR NAME",
                       st->file_path, st->focus_idx == 2, st->editing && st->focus_idx == 2);
        fy += 3;
        if (st->tab == TAB_PULL && fy + 2 < body_y + body_h - 4) {
            draw_field_row(c, fx, fy, fw, "LOCAL OUTPUT DIR  [B=Browse]", st->out_dir, st->focus_idx == 3, st->editing && st->focus_idx == 3);
            fy += 3;
        }
        if (fy + 2 < body_y + body_h - 3) {
            put_text(c, fx, fy, fw, "TRANSPORT LANE  [T=Cycle]", st->focus_idx == 4 ? COL_AURORA_CYAN : COL_TEXT_SEC, 0);
            int pw = (fw - 2) / 3;
            draw_pill(c, fx,          fy + 1, pw, "AUTO", st->transport_idx == 0, COL_AURORA_CYAN, COL_ACCENT_END);
            draw_pill(c, fx + pw + 1, fy + 1, pw, "UDP",  st->transport_idx == 1, COL_AURORA_CYAN, COL_ACCENT_END);
            draw_pill(c, fx + (pw+1)*2, fy + 1, pw, "TCP", st->transport_idx == 2, COL_AURORA_CYAN, COL_ACCENT_END);
            fy += 3;
        }
        if (fy < body_y + body_h - 3) {
            char opt[96];
            snprintf(opt, sizeof(opt), "Streams: %d  │  Ceiling: %d MiB/s  │  Overwrite: %s [O]",
                     st->tcp_streams, st->max_mbps, st->overwrite ? "ON" : "OFF");
            put_text(c, fx, fy, fw, opt, COL_TEXT_SEC, 0);
        }
        draw_pill(c, fx, body_y + body_h - 3, fw,
                  st->active_job ? "✕ CANCEL TRANSFER  [X]" : (st->tab == TAB_PUSH ? "⚡ LAUNCH HYBRID PUSH  [F5]" : "⚡ LAUNCH MERKLE PULL  [F5]"),
                  true,
                  st->active_job ? COL_ROSE : COL_AURORA_CYAN,
                  st->active_job ? COL_AURORA_MAG : COL_ACCENT_END);
    } else if (st->tab == TAB_SERVER) {
        draw_field_row(c, fx, fy, fw, "DUAL-STACK LISTEN ADDR (:9900 / :443)", st->listen_addr, st->focus_idx == 0, st->editing && st->focus_idx == 0);
        fy += 3;
        draw_field_row(c, fx, fy, fw, "ROOT STORAGE DIR  [B=Browse]", st->out_dir, st->focus_idx == 1, st->editing && st->focus_idx == 1);
        fy += 3;
        draw_field_row(c, fx, fy, fw, "256-BIT SERVER SECRET  [K=Keygen]", st->secret, st->focus_idx == 2, st->editing && st->focus_idx == 2);
        fy += 3;
        if (fy + 2 < body_y + body_h - 3) {
            char ov[64];
            snprintf(ov, sizeof(ov), "Allow Overwrite: %s  [O=Toggle]", st->overwrite ? "ENABLED" : "DISABLED");
            put_text(c, fx, fy, fw, ov, st->overwrite ? COL_MINT : COL_TEXT_SEC, 1);
            put_text(c, fx, fy + 2, fw, st->server_status[0] ? st->server_status : "Server idle — ready to bind TLS 1.3 + UDP",
                     st->server_handle ? COL_MINT : COL_TEXT_MUTED, 0);
        }
        draw_pill(c, fx, body_y + body_h - 3, fw,
                  st->server_handle ? "■ STOP DUAL-STACK SERVER  [F5]" : "▶ START DUAL-STACK SERVER  [F5]",
                  true,
                  st->server_handle ? COL_ROSE : COL_MINT,
                  st->server_handle ? COL_AURORA_MAG : COL_AURORA_CYAN);
    } else {
        put_text(c, fx, fy,     fw, "Built-in End-to-End Cryptographic Protocol Audit:", COL_TEXT_PRI, 1);
        put_text(c, fx, fy + 2, fw, "• Suite 1: 4 MiB Hybrid Auto Push + Pull (DEFLATE/Zero/Raw)", st->suite_idx >= 1 ? COL_AURORA_CYAN : COL_TEXT_SEC, 0);
        put_text(c, fx, fy + 3, fw, "• Suite 2: 17B Prepend Shift-Resistant Rabin CDC CAS",       st->suite_idx >= 2 ? COL_AURORA_CYAN : COL_TEXT_SEC, 0);
        put_text(c, fx, fy + 4, fw, "• Suite 3: 10% Burst-Loss Pure UDP + GF(256) RS FEC",          st->suite_idx >= 3 ? COL_AURORA_CYAN : COL_TEXT_SEC, 0);
        put_text(c, fx, fy + 5, fw, "• Suite 4: ISP UDP Blackhole -> TLS 1.3 Auto-Failover",        st->suite_idx >= 4 ? COL_MINT        : COL_TEXT_SEC, 0);
        put_text(c, fx, fy + 7, fw, "Zero external dependencies · Apache-2.0 clean-room engine", COL_TEXT_MUTED, 0);
        draw_pill(c, fx, body_y + body_h - 3, fw,
                  st->active_job ? "✕ CANCEL AUDIT  [X]" : "⚡ RUN 4-SUITE PROTOCOL AUDIT  [F5]",
                  true,
                  st->active_job ? COL_ROSE : COL_AURORA_CYAN,
                  st->active_job ? COL_AURORA_MAG : COL_ACCENT_END);
    }

    /* 3. Right Frosted Live Telemetry & Sparkline Card */
    draw_glass_card(c, right_x, body_y, right_w, body_h, false, false, "LIVE TELEMETRY · ZERO-COPY ENGINE");
    int rx = right_x + 2, rw = right_w - 4, ry = body_y + 2;

    /* Progress Bar + Stats Line */
    char prog_hdr[128], b_done[32], b_tot[32];
    format_bytes(st->bytes_done, b_done, sizeof(b_done));
    format_bytes(st->total_bytes, b_tot, sizeof(b_tot));
    snprintf(prog_hdr, sizeof(prog_hdr), "%5.1f%%  │  %s / %s  │  %s",
             st->percent, b_done, b_tot, st->active_lane[0] ? st->active_lane : "STANDBY");
    put_text(c, rx, ry, rw, prog_hdr, COL_TEXT_PRI, 1);
    draw_progress_bar(c, rx, ry + 1, rw, st->percent);

    /* 4 Frosted KPI Micro-Tiles (2x2 Grid) */
    int kpi_y = ry + 3;
    int tile_w = (rw - 1) / 2;
    if (tile_w >= 14 && kpi_y + 6 < body_y + body_h) {
        char v1[64], v2[64], v3[64], v4[64];
        snprintf(v1, sizeof(v1), "%.2f MiB/s", st->goodput_mbps);
        char u_str[24], t_str[24];
        format_bytes((int64_t)st->wire_udp, u_str, sizeof(u_str));
        format_bytes((int64_t)st->wire_tcp, t_str, sizeof(t_str));
        snprintf(v2, sizeof(v2), "U:%s T:%s", u_str, t_str);
        snprintf(v3, sizeof(v3), "CAS:%u Z:%u D:%u", st->cas_blocks, st->zero_blocks, st->comp_blocks);
        snprintf(v4, sizeof(v4), "Rec:%u FO:%u %.1fms", st->fec_recovered, st->failover_blocks, st->rtt_ms);

        draw_glass_card(c, rx,              kpi_y,     tile_w, 3, true, false, "GOODPUT");
        put_text(c,        rx + 2,          kpi_y + 1, tile_w - 4, v1, COL_AURORA_CYAN, 1);

        draw_glass_card(c, rx + tile_w + 1, kpi_y,     rw - tile_w - 1, 3, true, false, "WIRE I/O");
        put_text(c,        rx + tile_w + 3, kpi_y + 1, rw - tile_w - 5, v2, COL_TEXT_MONO, 1);

        draw_glass_card(c, rx,              kpi_y + 3, tile_w, 3, true, false, "CDC CAS / DEDUP");
        put_text(c,        rx + 2,          kpi_y + 4, tile_w - 4, v3, COL_MINT, 1);

        draw_glass_card(c, rx + tile_w + 1, kpi_y + 3, rw - tile_w - 1, 3, true, false, "GF(256) RS FEC");
        put_text(c,        rx + tile_w + 3, kpi_y + 4, rw - tile_w - 5, v4,
                 st->fec_recovered || st->failover_blocks ? COL_AMBER : COL_TEXT_PRI, 1);
    }

    /* High-Res 2x4 Sub-Pixel Braille Throughput Sparkline */
    int sp_y = kpi_y + 7;
    int sp_h = (body_y + body_h - 4) - sp_y;
    if (sp_h >= 4) {
        draw_glass_card(c, rx, sp_y, rw, sp_h, true, false, "THROUGHPUT SPARKLINE (MiB/s)");
        draw_braille_sparkline(c, rx + 2, sp_y + 1, rw - 4, sp_h - 2, st->spark, 60);
    }

    /* Cryptographic Merkle Root Strip */
    int mk_y = body_y + body_h - 3;
    char mk_line[160];
    if (st->merkle_hex[0]) {
        snprintf(mk_line, sizeof(mk_line), "✓ MERKLE SHA-256: %s", st->merkle_hex);
        put_text(c, rx, mk_y, rw, mk_line, COL_MINT, 1);
    } else {
        put_text(c, rx, mk_y, rw, st->message[0] ? st->message : "Ready · Standard TLS 1.3 + X25519-PFS UDP GSO/FEC",
                 strcmp(st->phase, "error") == 0 ? COL_ROSE : COL_TEXT_SEC, 0);
    }

    /* 4. Bottom Frosted Keybind Hint Strip */
    put_text(c, 2, H - 1, W - 4,
             "[1-4] Tabs  [↑/↓/Tab] Focus  [Enter] Edit  [F5] Launch/Stop  [K] Keygen  [B] Browse  [T] Lane  [O] Overwrite  [Q] Quit",
             COL_TEXT_MUTED, 0);

    /* 5. Optional Frosted File Browser Modal */
    if (st->browser_open) {
        int mw = W * 70 / 100; if (mw < 44) mw = 44;
        int mh = H * 72 / 100; if (mh < 12) mh = 12;
        int mx = (W - mw) / 2, my = (H - mh) / 2;
        draw_glass_card(c, mx, my, mw, mh, true, true,
                        st->browser_for_dir ? "SELECT DIRECTORY (Enter=Open · S=Select Here · Esc=Close)"
                                            : "SELECT FILE / DIR (Enter=Open/Select · S=Select Dir · Esc=Close)");
        put_text(c, mx + 2, my + 1, mw - 4, st->browser_cwd, COL_AURORA_CYAN, 1);

        int list_h = mh - 4;
        int start_i = 0;
        if (st->browser_sel >= list_h) start_i = st->browser_sel - list_h + 1;
        for (int r = 0; r < list_h && start_i + r < st->item_count; r++) {
            int idx = start_i + r;
            DirItem *it = &st->items[idx];
            bool sel = (idx == st->browser_sel);
            int ly = my + 2 + r;
            if (sel) {
                draw_pill(c, mx + 2, ly, mw - 4, "", true, COL_AURORA_CYAN, COL_ACCENT_END);
            }
            char row[320], sz[32];
            if (it->is_dir) snprintf(row, sizeof(row), " 📁 %s/", it->name);
            else {
                format_bytes((int64_t)it->size, sz, sizeof(sz));
                snprintf(row, sizeof(row), " 📄 %-36s %10s", it->name, sz);
            }
            put_text(c, mx + 2, ly, mw - 4, row, sel ? COL_BG_VOID : (it->is_dir ? COL_TEXT_MONO : COL_TEXT_PRI), sel ? 1 : 0);
        }
    }

    pthread_mutex_unlock(&st->mu);
}

/* ============================================================================
 * Raw POSIX Terminal Setup + Input Handling (Keyboard + SGR 1006 Mouse)
 * ============================================================================ */
static struct termios g_orig_termios;
static bool g_raw_enabled = false;
static volatile sig_atomic_t g_quit = 0;
static volatile sig_atomic_t g_resized = 0;

static void handle_sig(int sig) {
    if (sig == SIGWINCH) g_resized = 1;
    else g_quit = 1;
}

static void restore_terminal(void) {
    if (g_raw_enabled) {
        const char *seq = "\x1b[?1006l\x1b[?1000l\x1b[?25h\x1b[?1049l\x1b[0m";
        ssize_t _ignored = write(STDOUT_FILENO, seq, strlen(seq));
        (void)_ignored;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
        g_raw_enabled = false;
    }
}

static bool enable_raw_terminal(void) {
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) return false;
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) != 0) return false;
    struct termios raw = g_orig_termios;
    raw.c_iflag &= (tcflag_t)~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= (tcflag_t)~(OPOST);
    raw.c_cflag |= (tcflag_t)(CS8);
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) return false;
    g_raw_enabled = true;
    atexit(restore_terminal);
    const char *init = "\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?1006h";
    ssize_t _ignored = write(STDOUT_FILENO, init, strlen(init));
    (void)_ignored;
    return true;
}

static char *active_field_buf(AppState *st, size_t *cap) {
    if (st->tab == TAB_SERVER) {
        if (st->focus_idx == 0) { *cap = sizeof(st->listen_addr); return st->listen_addr; }
        if (st->focus_idx == 1) { *cap = sizeof(st->out_dir);     return st->out_dir; }
        if (st->focus_idx == 2) { *cap = sizeof(st->secret);      return st->secret; }
        return NULL;
    }
    if (st->tab == TAB_PUSH || st->tab == TAB_PULL) {
        if (st->focus_idx == 0) { *cap = sizeof(st->server_addr); return st->server_addr; }
        if (st->focus_idx == 1) { *cap = sizeof(st->secret);      return st->secret; }
        if (st->focus_idx == 2) { *cap = sizeof(st->file_path);   return st->file_path; }
        if (st->focus_idx == 3 && st->tab == TAB_PULL) { *cap = sizeof(st->out_dir); return st->out_dir; }
    }
    return NULL;
}

static void handle_mouse_click(AppState *st, int mx, int my, int W, int H) {
    /* Header tabs row (y == 1) */
    if (my == 1) {
        int tx = 26;
        for (int i = 0; i < 4; i++) {
            if (mx >= tx && mx < tx + 11) {
                st->tab = (TabID)i;
                st->focus_idx = 0;
                st->editing = false;
                return;
            }
            tx += 12;
        }
    }
    int left_w = (W - 3) * 46 / 100;
    if (left_w < 34) left_w = 34;
    int body_h = H - 5;
    if (mx >= 3 && mx < left_w - 1 && my == 3 + body_h - 3) {
        trigger_primary_action(st);
    }
}

static void process_input(AppState *st, int W, int H) {
    unsigned char buf[64];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n <= 0) return;
    buf[n] = 0;

    /* Ctrl-C quits cleanly */
    if (buf[0] == 3) { g_quit = 1; return; }

    /* SGR 1006 Mouse sequence: \x1b[<btn;x;yM */
    if (n >= 6 && buf[0] == 0x1b && buf[1] == '[' && buf[2] == '<') {
        int btn = 0, mx = 0, my = 0;
        char kind = 0;
        if (sscanf((char *)buf + 3, "%d;%d;%d%c", &btn, &mx, &my, &kind) == 4 && kind == 'M' && btn == 0) {
            handle_mouse_click(st, mx - 1, my - 1, W, H);
        }
        return;
    }

    /* File browser modal keys */
    if (st->browser_open) {
        if (buf[0] == 0x1b && n == 1) { st->browser_open = false; return; }
        if (n >= 3 && buf[0] == 0x1b && buf[1] == '[') {
            if (buf[2] == 'A' && st->browser_sel > 0) st->browser_sel--;
            else if (buf[2] == 'B' && st->browser_sel + 1 < st->item_count) st->browser_sel++;
            return;
        }
        if (buf[0] == 's' || buf[0] == 'S') {
            if (st->browser_for_dir) snprintf(st->out_dir, sizeof(st->out_dir), "%s", st->browser_cwd);
            else snprintf(st->file_path, sizeof(st->file_path), "%s", st->browser_cwd);
            st->browser_open = false;
            return;
        }
        if (buf[0] == '\r' || buf[0] == '\n') {
            if (st->browser_sel >= 0 && st->browser_sel < st->item_count) {
                DirItem *it = &st->items[st->browser_sel];
                if (strcmp(it->name, "..") == 0) {
                    char *sl = strrchr(st->browser_cwd, '/');
                    if (sl && sl != st->browser_cwd) *sl = '\0';
                    else memcpy(st->browser_cwd, "/", 2);
                    browser_load(st, st->browser_cwd);
                } else if (it->is_dir) {
                    char next[1024];
                    int wn = snprintf(next, sizeof(next), "%s/%s",
                                      strcmp(st->browser_cwd, "/") == 0 ? "" : st->browser_cwd, it->name);
                    if (wn > 0 && (size_t)wn < sizeof(st->browser_cwd)) {
                        memcpy(st->browser_cwd, next, (size_t)wn + 1);
                        browser_load(st, st->browser_cwd);
                    }
                } else if (!st->browser_for_dir) {
                    char next[1024];
                    int wn = snprintf(next, sizeof(next), "%s/%s",
                                      strcmp(st->browser_cwd, "/") == 0 ? "" : st->browser_cwd, it->name);
                    if (wn > 0 && (size_t)wn < sizeof(st->file_path)) {
                        memcpy(st->file_path, next, (size_t)wn + 1);
                        st->browser_open = false;
                    }
                }
            }
        }
        return;
    }

    /* F5 launches/stops active tab */
    if (n >= 5 && memcmp(buf, "\x1b[15~", 5) == 0) {
        st->editing = false;
        trigger_primary_action(st);
        return;
    }

    /* Inline text editing mode */
    if (st->editing) {
        size_t cap = 0;
        char *fld = active_field_buf(st, &cap);
        if (buf[0] == 0x1b || buf[0] == '\r' || buf[0] == '\n') {
            st->editing = false;
            return;
        }
        if (fld) {
            size_t len = strlen(fld);
            if (buf[0] == 127 || buf[0] == 8) {
                if (len > 0) fld[len - 1] = '\0';
            } else if (buf[0] >= 0x20 && buf[0] < 0x7f && len + 1 < cap) {
                fld[len] = (char)buf[0];
                fld[len + 1] = '\0';
            }
        }
        return;
    }

    /* Navigation mode */
    int max_focus = (st->tab == TAB_PULL) ? 4 : (st->tab == TAB_PUSH ? 4 : (st->tab == TAB_SERVER ? 2 : 0));
    if (n >= 3 && buf[0] == 0x1b && buf[1] == '[') {
        if (buf[2] == 'A') st->focus_idx = (st->focus_idx > 0) ? st->focus_idx - 1 : max_focus;
        else if (buf[2] == 'B') st->focus_idx = (st->focus_idx < max_focus) ? st->focus_idx + 1 : 0;
        return;
    }
    switch (buf[0]) {
        case 'q': case 'Q': g_quit = 1; break;
        case '1': st->tab = TAB_PUSH;   st->focus_idx = 0; break;
        case '2': st->tab = TAB_PULL;   st->focus_idx = 0; break;
        case '3': st->tab = TAB_SERVER; st->focus_idx = 0; break;
        case '4': st->tab = TAB_AUDIT;  st->focus_idx = 0; break;
        case '\t': st->focus_idx = (st->focus_idx < max_focus) ? st->focus_idx + 1 : 0; break;
        case '\r': case '\n':
            if (st->tab == TAB_AUDIT) trigger_primary_action(st);
            else {
                size_t cap = 0;
                if (active_field_buf(st, &cap) != NULL) st->editing = true;
                else trigger_primary_action(st);
            }
            break;
        case 'k': case 'K': trigger_keygen(st); break;
        case 't': case 'T': st->transport_idx = (st->transport_idx + 1) % 3; break;
        case 'o': case 'O': st->overwrite = !st->overwrite; break;
        case 'x': case 'X':
            if (st->active_job) trigger_primary_action(st);
            break;
        case 'b': case 'B':
            st->browser_for_dir = (st->tab == TAB_SERVER || (st->tab == TAB_PULL && st->focus_idx == 3));
            if (!getcwd(st->browser_cwd, sizeof(st->browser_cwd))) snprintf(st->browser_cwd, sizeof(st->browser_cwd), ".");
            browser_load(st, st->browser_cwd);
            st->browser_open = true;
            break;
        default: break;
    }
}

/* ============================================================================
 * Automated CI / Headless Smoke Test (`openfir-tui --smoke-test`)
 * ============================================================================ */
static int run_smoke_test(AppState *st) {
    char key[80] = {0};
    if (openfir_keygen(key, sizeof(key)) != 64) {
        fprintf(stderr, "[TUI SmokeTest] openfir_keygen failed\n");
        return 1;
    }
    snprintf(st->secret, sizeof(st->secret), "%s", key);

    /* Start live 4-suite protocol audit through C ABI */
    st->tab = TAB_AUDIT;
    uint64_t j = openfir_selftest_start(on_openfir_event, st);
    if (j == 0) {
        fprintf(stderr, "[TUI SmokeTest] openfir_selftest_start returned 0\n");
        return 2;
    }
    pthread_mutex_lock(&st->mu);
    st->active_job = j;
    pthread_mutex_unlock(&st->mu);

    Canvas cv;
    canvas_init(&cv);
    canvas_resize(&cv, 120, 34);

    bool done = false;
    bool ok = false;
    for (int step = 0; step < 300; step++) {
        render_ui(&cv, st, step * 0.05);
        canvas_flush(&cv, -1); /* Render into ANSI buffer without requiring a TTY */

        pthread_mutex_lock(&st->mu);
        if (strcmp(st->phase, "done") == 0)  { done = true; ok = true; }
        if (strcmp(st->phase, "error") == 0) { done = true; ok = false; }
        pthread_mutex_unlock(&st->mu);
        if (done) break;
        struct timespec ts = {0, 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }

    /* Verify TrueColor frosted glass + Braille sparkline ANSI frame output */
    bool has_tc = (strstr(cv.out_buf, "\x1b[") != NULL && strstr(cv.out_buf, "38;2;") != NULL);
    printf("[TUI SmokeTest] version=%s phase=%s merkle=%.16s... ansi_bytes=%zu truecolor=%s\n",
           openfir_version(), st->phase, st->merkle_hex, cv.out_len, has_tc ? "yes" : "no");
    canvas_free(&cv);
    return (ok && has_tc && st->merkle_hex[0] != '\0') ? 0 : 3;
}

int main(int argc, char **argv) {
    AppState st;
    memset(&st, 0, sizeof(st));
    pthread_mutex_init(&st.mu, NULL);
    st.tab = TAB_PUSH;
    snprintf(st.server_addr, sizeof(st.server_addr), "127.0.0.1:9900");
    snprintf(st.listen_addr, sizeof(st.listen_addr), ":9900");
    snprintf(st.out_dir, sizeof(st.out_dir), "./openfir_data");
    snprintf(st.phase, sizeof(st.phase), "idle");
    st.tcp_streams = 4;
    st.max_mbps = 1000;
    st.overwrite = true;
    trigger_keygen(&st);

    if (argc > 1 && strcmp(argv[1], "--smoke-test") == 0) {
        int rc = run_smoke_test(&st);
        free(st.items);
        pthread_mutex_destroy(&st.mu);
        return rc;
    }

    if (!enable_raw_terminal()) {
        fprintf(stderr, "openfir-tui requires an interactive TTY (or pass --smoke-test).\n");
        return 1;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);
    signal(SIGWINCH, handle_sig);

    Canvas cv;
    canvas_init(&cv);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    while (!g_quit) {
        struct winsize ws;
        int w = 120, h = 34;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
            w = ws.ws_col;
            h = ws.ws_row;
        }
        if (g_resized) {
            g_resized = 0;
            cv.force_full = true;
        }
        canvas_resize(&cv, w, h);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (double)(now.tv_sec - t0.tv_sec) + (double)(now.tv_nsec - t0.tv_nsec) * 1e-9;

        render_ui(&cv, &st, elapsed);
        canvas_flush(&cv, STDOUT_FILENO);

        struct pollfd pfd = {.fd = STDIN_FILENO, .events = POLLIN};
        if (poll(&pfd, 1, 33) > 0 && (pfd.revents & POLLIN)) {
            process_input(&st, cv.w, cv.h);
        }
    }

    if (st.active_job) openfir_transfer_cancel(st.active_job);
    if (st.server_handle) openfir_server_stop(st.server_handle);
    canvas_free(&cv);
    free(st.items);
    pthread_mutex_destroy(&st.mu);
    restore_terminal();
    return 0;
}
