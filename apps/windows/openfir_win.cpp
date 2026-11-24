// SPDX-License-Identifier: Apache-2.0
//
// OpenFIR Windows Native Frosted-Glass GUI (OpenFIR.exe)
// Pure C++20 + Win32 + Direct2D + DirectWrite + Windows 11 DWM Acrylic.
// ZERO third-party dependencies (no Qt, no Electron, no WebView2, no WinUI NuGet).
// Loads `openfir_core.dll` dynamically via LoadLibraryW for clean MSVC/Go ABI interop.

#define UNICODE
#define _UNICODE
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commdlg.h>
#include <d2d1.h>
#include <dwmapi.h>
#include <dwrite.h>
#include <shobjidl.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")

namespace {

// ============================================================================
// Dynamic OpenFIR Core C ABI Loader (`openfir_core.dll`)
// ============================================================================
using openfir_event_cb_fn        = void (*)(uint64_t handle, const char *json_utf8, void *user_ctx);
using openfir_version_fn         = const char *(*)(void);
using openfir_keygen_fn          = int (*)(char *out_hex, size_t out_cap);
using openfir_transfer_start_fn  = uint64_t (*)(const char *config_json, openfir_event_cb_fn cb, void *user_ctx);
using openfir_transfer_cancel_fn = void (*)(uint64_t job_id);
using openfir_server_start_fn    = uint64_t (*)(const char *config_json, openfir_event_cb_fn cb, void *user_ctx);
using openfir_server_stop_fn     = void (*)(uint64_t server_handle);
using openfir_selftest_start_fn  = uint64_t (*)(openfir_event_cb_fn cb, void *user_ctx);

struct CoreAPI {
    HMODULE mod = nullptr;
    openfir_version_fn         version = nullptr;
    openfir_keygen_fn          keygen = nullptr;
    openfir_transfer_start_fn  transfer_start = nullptr;
    openfir_transfer_cancel_fn transfer_cancel = nullptr;
    openfir_server_start_fn    server_start = nullptr;
    openfir_server_stop_fn     server_stop = nullptr;
    openfir_selftest_start_fn  selftest_start = nullptr;

    bool load() {
        wchar_t exePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring dir(exePath);
        auto slash = dir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) dir = dir.substr(0, slash + 1);
        std::wstring dllPath = dir + L"openfir_core.dll";

        mod = LoadLibraryW(dllPath.c_str());
        if (!mod) mod = LoadLibraryW(L"openfir_core.dll");
        if (!mod) return false;

        version         = reinterpret_cast<openfir_version_fn>(GetProcAddress(mod, "openfir_version"));
        keygen          = reinterpret_cast<openfir_keygen_fn>(GetProcAddress(mod, "openfir_keygen"));
        transfer_start  = reinterpret_cast<openfir_transfer_start_fn>(GetProcAddress(mod, "openfir_transfer_start"));
        transfer_cancel = reinterpret_cast<openfir_transfer_cancel_fn>(GetProcAddress(mod, "openfir_transfer_cancel"));
        server_start    = reinterpret_cast<openfir_server_start_fn>(GetProcAddress(mod, "openfir_server_start"));
        server_stop     = reinterpret_cast<openfir_server_stop_fn>(GetProcAddress(mod, "openfir_server_stop"));
        selftest_start  = reinterpret_cast<openfir_selftest_start_fn>(GetProcAddress(mod, "openfir_selftest_start"));
        return version && keygen && transfer_start && transfer_cancel && server_start && server_stop && selftest_start;
    }
};

CoreAPI g_core;

// ============================================================================
// Obsidian Frost x Neon Aurora Canonical Direct2D Palette
// ============================================================================
inline D2D1_COLOR_F d2d_rgb(uint8_t r, uint8_t g, uint8_t b, float a = 1.0f) {
    return D2D1::ColorF(r / 255.0f, g / 255.0f, b / 255.0f, a);
}

const D2D1_COLOR_F C_VOID        = d2d_rgb(  7,   9,  19, 1.00f);
const D2D1_COLOR_F C_CYAN        = d2d_rgb(  0, 240, 255, 1.00f);
const D2D1_COLOR_F C_VIOLET      = d2d_rgb(139,  92, 246, 1.00f);
const D2D1_COLOR_F C_ACCENT_END  = d2d_rgb(124,  58, 237, 1.00f);
const D2D1_COLOR_F C_MAGENTA     = d2d_rgb(236,  72, 153, 1.00f);
const D2D1_COLOR_F C_GLASS_SURF  = d2d_rgb( 17,  23,  42, 0.64f);
const D2D1_COLOR_F C_GLASS_ELEV  = d2d_rgb( 26,  35,  62, 0.78f);
const D2D1_COLOR_F C_GLASS_INPUT = d2d_rgb( 10,  15,  29, 0.80f);
const D2D1_COLOR_F C_MINT        = d2d_rgb( 16, 249, 160, 1.00f);
const D2D1_COLOR_F C_AMBER       = d2d_rgb(255, 176,  32, 1.00f);
const D2D1_COLOR_F C_ROSE        = d2d_rgb(255,  77, 141, 1.00f);
const D2D1_COLOR_F C_TEXT_PRI    = d2d_rgb(248, 250, 252, 1.00f);
const D2D1_COLOR_F C_TEXT_SEC    = d2d_rgb(148, 163, 184, 1.00f);
const D2D1_COLOR_F C_TEXT_MUTED  = d2d_rgb(100, 116, 139, 1.00f);
const D2D1_COLOR_F C_TEXT_MONO   = d2d_rgb(125, 211, 252, 1.00f);

std::wstring utf8_to_wide(const std::string &s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string wide_to_utf8(const std::wstring &w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

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

inline bool pt_in(const D2D1_RECT_F &r, float x, float y) {
    return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
}

enum class Tab { Push = 0, Pull = 1, Server = 2, Audit = 3 };

struct AppState {
    std::mutex mu;
    Tab tab = Tab::Push;
    int focus_field = 0;

    std::string server_addr = "127.0.0.1:9900";
    std::string secret;
    std::string file_path;
    std::string out_dir = ".\\openfir_data";
    std::string listen_addr = ":9900";
    int transport_idx = 0;
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

    // Hitboxes
    D2D1_RECT_F rc_tabs[4]{};
    D2D1_RECT_F rc_fields[4]{};
    D2D1_RECT_F rc_keygen{};
    D2D1_RECT_F rc_browse{};
    D2D1_RECT_F rc_modes[3]{};
    D2D1_RECT_F rc_overwrite{};
    D2D1_RECT_F rc_cta{};
};

void on_engine_event(uint64_t handle, const char *json, void *ctx) {
    auto *st = static_cast<AppState *>(ctx);
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
    if (phase == "done" || phase == "error") st->active_job = 0;
}

void do_keygen(AppState &st) {
    char key[80]{};
    if (g_core.keygen && g_core.keygen(key, sizeof(key)) == 64) {
        std::lock_guard<std::mutex> lk(st.mu);
        st.secret = key;
        st.message = "Generated fresh 256-bit cryptographically secure key";
    }
}

void trigger_cta(AppState &st) {
    std::unique_lock<std::mutex> lk(st.mu);
    if (st.tab == Tab::Server) {
        if (st.server_handle != 0) {
            uint64_t h = st.server_handle;
            st.server_handle = 0;
            st.phase = "idle";
            st.server_status = "Server stopped";
            st.message = "Dual-stack server stopped cleanly";
            lk.unlock();
            g_core.server_stop(h);
            return;
        }
        std::string cfg = "{\"listen\":\"" + json_esc(st.listen_addr) +
                          "\",\"dir\":\"" + json_esc(st.out_dir) +
                          "\",\"secret\":\"" + json_esc(st.secret) +
                          "\",\"overwrite\":" + (st.overwrite ? "true" : "false") +
                          ",\"max_sessions\":64}";
        lk.unlock();
        uint64_t h = g_core.server_start(cfg.c_str(), on_engine_event, &st);
        lk.lock();
        st.server_handle = h;
        return;
    }
    if (st.active_job != 0) {
        uint64_t j = st.active_job;
        st.active_job = 0;
        st.phase = "idle";
        st.message = "Transfer cancelled";
        lk.unlock();
        g_core.transfer_cancel(j);
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
        uint64_t j = g_core.selftest_start(on_engine_event, &st);
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
    uint64_t j = g_core.transfer_start(cfg.c_str(), on_engine_event, &st);
    lk.lock();
    if (j != 0) st.active_job = j;
}

std::string pick_file_or_folder(HWND hwnd, bool folder_only) {
    if (folder_only) {
        IFileDialog *pfd = nullptr;
        std::string res;
        if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pfd)))) {
            DWORD opts = 0;
            pfd->GetOptions(&opts);
            pfd->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
            if (SUCCEEDED(pfd->Show(hwnd))) {
                IShellItem *item = nullptr;
                if (SUCCEEDED(pfd->GetResult(&item))) {
                    PWSTR path = nullptr;
                    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                        res = wide_to_utf8(path);
                        CoTaskMemFree(path);
                    }
                    item->Release();
                }
            }
            pfd->Release();
        }
        return res;
    }
    wchar_t buf[MAX_PATH * 2]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH * 2;
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) return wide_to_utf8(buf);
    return "";
}

// ============================================================================
// Direct2D + DirectWrite Frosted-Glass Renderer
// ============================================================================
class FrostWindow {
public:
    HWND hwnd = nullptr;
    AppState st;

    ID2D1Factory *d2d_fac = nullptr;
    ID2D1HwndRenderTarget *rt = nullptr;
    IDWriteFactory *dw_fac = nullptr;
    IDWriteTextFormat *tf_body = nullptr;
    IDWriteTextFormat *tf_bold = nullptr;
    IDWriteTextFormat *tf_title = nullptr;
    IDWriteTextFormat *tf_mono = nullptr;
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();

    void init_factories() {
        D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &d2d_fac);
        DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), reinterpret_cast<IUnknown **>(&dw_fac));
        if (dw_fac) {
            dw_fac->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_REGULAR, DWRITE_FONT_STYLE_NORMAL,
                                     DWRITE_FONT_STRETCH_NORMAL, 13.0f, L"en-us", &tf_body);
            dw_fac->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL,
                                     DWRITE_FONT_STRETCH_NORMAL, 13.5f, L"en-us", &tf_bold);
            dw_fac->CreateTextFormat(L"Segoe UI", nullptr, DWRITE_FONT_WEIGHT_BOLD, DWRITE_FONT_STYLE_NORMAL,
                                     DWRITE_FONT_STRETCH_NORMAL, 19.0f, L"en-us", &tf_title);
            dw_fac->CreateTextFormat(L"Cascadia Mono", nullptr, DWRITE_FONT_WEIGHT_REGULAR, DWRITE_FONT_STYLE_NORMAL,
                                     DWRITE_FONT_STRETCH_NORMAL, 12.5f, L"en-us", &tf_mono);
        }
    }

    void ensure_rt() {
        if (rt || !d2d_fac || !hwnd) return;
        RECT rc{};
        GetClientRect(hwnd, &rc);
        D2D1_SIZE_U sz = D2D1::SizeU(std::max<UINT>(1, rc.right - rc.left), std::max<UINT>(1, rc.bottom - rc.top));
        d2d_fac->CreateHwndRenderTarget(D2D1::RenderTargetProperties(),
                                        D2D1::HwndRenderTargetProperties(hwnd, sz), &rt);
    }

    void discard_rt() {
        if (rt) { rt->Release(); rt = nullptr; }
    }

    void fill_gradient_rr(const D2D1_RECT_F &r, float rad, D2D1_COLOR_F c0, D2D1_COLOR_F c1) {
        D2D1_GRADIENT_STOP stops[2] = {{0.0f, c0}, {1.0f, c1}};
        ID2D1GradientStopCollection *col = nullptr;
        if (FAILED(rt->CreateGradientStopCollection(stops, 2, &col))) return;
        ID2D1LinearGradientBrush *br = nullptr;
        if (SUCCEEDED(rt->CreateLinearGradientBrush(
                D2D1::LinearGradientBrushProperties(D2D1::Point2F(r.left, r.top), D2D1::Point2F(r.right, r.bottom)),
                col, &br))) {
            rt->FillRoundedRectangle(D2D1::RoundedRect(r, rad, rad), br);
            br->Release();
        }
        col->Release();
    }

    void draw_glass_card(const D2D1_RECT_F &r, float rad, bool elevated, bool active_rim) {
        ID2D1SolidColorBrush *fill = nullptr;
        rt->CreateSolidColorBrush(elevated ? C_GLASS_ELEV : C_GLASS_SURF, &fill);
        if (fill) {
            rt->FillRoundedRectangle(D2D1::RoundedRect(r, rad, rad), fill);
            fill->Release();
        }
        // Top specular glass highlight band
        D2D1_RECT_F sheen = D2D1::RectF(r.left + 1.0f, r.top + 1.0f, r.right - 1.0f, r.top + 38.0f);
        fill_gradient_rr(sheen, rad, d2d_rgb(255, 255, 255, 0.08f), d2d_rgb(255, 255, 255, 0.0f));

        // 1px Cyan->Violet neon specular frosted border
        D2D1_GRADIENT_STOP stops[2] = {
            {0.0f, active_rim ? d2d_rgb(0, 240, 255, 0.72f) : d2d_rgb(180, 235, 255, 0.24f)},
            {1.0f, active_rim ? d2d_rgb(139, 92, 246, 0.65f) : d2d_rgb(139, 92, 246, 0.16f)}
        };
        ID2D1GradientStopCollection *col = nullptr;
        if (SUCCEEDED(rt->CreateGradientStopCollection(stops, 2, &col))) {
            ID2D1LinearGradientBrush *rim = nullptr;
            if (SUCCEEDED(rt->CreateLinearGradientBrush(
                    D2D1::LinearGradientBrushProperties(D2D1::Point2F(r.left, r.top), D2D1::Point2F(r.right, r.bottom)),
                    col, &rim))) {
                rt->DrawRoundedRectangle(D2D1::RoundedRect(r, rad, rad), rim, active_rim ? 1.4f : 1.0f);
                rim->Release();
            }
            col->Release();
        }
    }

    void draw_text(const std::string &s, const D2D1_RECT_F &r, D2D1_COLOR_F c, IDWriteTextFormat *tf) {
        if (!tf || s.empty()) return;
        std::wstring w = utf8_to_wide(s);
        ID2D1SolidColorBrush *br = nullptr;
        if (SUCCEEDED(rt->CreateSolidColorBrush(c, &br))) {
            rt->DrawTextW(w.c_str(), static_cast<UINT32>(w.size()), tf, r, br, D2D1_DRAW_TEXT_OPTIONS_CLIP);
            br->Release();
        }
    }

    void draw_aurora_orb(float cx, float cy, float rx, float ry, D2D1_COLOR_F col) {
        D2D1_GRADIENT_STOP stops[2] = {{0.0f, col}, {1.0f, d2d_rgb(7, 9, 19, 0.0f)}};
        ID2D1GradientStopCollection *gsc = nullptr;
        if (FAILED(rt->CreateGradientStopCollection(stops, 2, &gsc))) return;
        ID2D1RadialGradientBrush *rb = nullptr;
        if (SUCCEEDED(rt->CreateRadialGradientBrush(
                D2D1::RadialGradientBrushProperties(D2D1::Point2F(cx, cy), D2D1::Point2F(0, 0), rx, ry),
                gsc, &rb))) {
            rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), rx, ry), rb);
            rb->Release();
        }
        gsc->Release();
    }

    void draw_sparkline(const D2D1_RECT_F &r, const double *samples, int count) {
        if (count < 2 || !d2d_fac) return;
        double max_v = 1.0;
        for (int i = 0; i < count; ++i) max_v = std::max(max_v, samples[i]);
        float w = r.right - r.left, h = r.bottom - r.top;

        ID2D1PathGeometry *stroke_geo = nullptr;
        ID2D1PathGeometry *area_geo = nullptr;
        d2d_fac->CreatePathGeometry(&stroke_geo);
        d2d_fac->CreatePathGeometry(&area_geo);
        if (!stroke_geo || !area_geo) {
            if (stroke_geo) stroke_geo->Release();
            if (area_geo) area_geo->Release();
            return;
        }
        ID2D1GeometrySink *ss = nullptr, *as = nullptr;
        stroke_geo->Open(&ss);
        area_geo->Open(&as);

        auto pt = [&](int i) {
            float x = r.left + w * static_cast<float>(i) / (count - 1);
            float y = r.bottom - 4.0f - static_cast<float>(std::clamp(samples[i] / max_v, 0.0, 1.0)) * (h - 10.0f);
            return D2D1::Point2F(x, y);
        };
        D2D1_POINT_2F p0 = pt(0);
        ss->BeginFigure(p0, D2D1_FIGURE_BEGIN_HOLLOW);
        as->BeginFigure(D2D1::Point2F(r.left, r.bottom), D2D1_FIGURE_BEGIN_FILLED);
        as->AddLine(p0);
        for (int i = 1; i < count; ++i) {
            D2D1_POINT_2F pi = pt(i);
            ss->AddLine(pi);
            as->AddLine(pi);
        }
        as->AddLine(D2D1::Point2F(r.right, r.bottom));
        ss->EndFigure(D2D1_FIGURE_END_OPEN);
        as->EndFigure(D2D1_FIGURE_END_CLOSED);
        ss->Close(); as->Close();
        ss->Release(); as->Release();

        D2D1_GRADIENT_STOP astops[2] = {{0.0f, d2d_rgb(0, 240, 255, 0.28f)}, {1.0f, d2d_rgb(139, 92, 246, 0.02f)}};
        ID2D1GradientStopCollection *ac = nullptr;
        if (SUCCEEDED(rt->CreateGradientStopCollection(astops, 2, &ac))) {
            ID2D1LinearGradientBrush *ab = nullptr;
            if (SUCCEEDED(rt->CreateLinearGradientBrush(
                    D2D1::LinearGradientBrushProperties(D2D1::Point2F(r.left, r.top), D2D1::Point2F(r.left, r.bottom)),
                    ac, &ab))) {
                rt->FillGeometry(area_geo, ab);
                ab->Release();
            }
            ac->Release();
        }
        D2D1_GRADIENT_STOP sstops[2] = {{0.0f, C_CYAN}, {1.0f, C_VIOLET}};
        ID2D1GradientStopCollection *sc = nullptr;
        if (SUCCEEDED(rt->CreateGradientStopCollection(sstops, 2, &sc))) {
            ID2D1LinearGradientBrush *sb = nullptr;
            if (SUCCEEDED(rt->CreateLinearGradientBrush(
                    D2D1::LinearGradientBrushProperties(D2D1::Point2F(r.left, r.top), D2D1::Point2F(r.right, r.top)),
                    sc, &sb))) {
                rt->DrawGeometry(stroke_geo, sb, 2.2f);
                sb->Release();
            }
            sc->Release();
        }
        stroke_geo->Release();
        area_geo->Release();
    }

    void render() {
        ensure_rt();
        if (!rt) return;

        D2D1_SIZE_F sz = rt->GetSize();
        float W = sz.width, H = sz.height;
        float t = std::chrono::duration<float>(std::chrono::steady_clock::now() - t0).count();

        rt->BeginDraw();
        rt->Clear(C_VOID);

        // Animated Obsidian Frost x Neon Aurora GPU radial plasma
        draw_aurora_orb(W * (0.20f + 0.06f * std::sin(t * 0.45f)), H * (0.22f + 0.06f * std::cos(t * 0.37f)),
                        W * 0.42f, H * 0.48f, d2d_rgb(0, 240, 255, 0.28f));
        draw_aurora_orb(W * (0.80f + 0.07f * std::cos(t * 0.32f)), H * (0.78f + 0.06f * std::sin(t * 0.41f)),
                        W * 0.46f, H * 0.50f, d2d_rgb(139, 92, 246, 0.30f));
        draw_aurora_orb(W * (0.58f + 0.08f * std::sin(t * 0.27f + 1.2f)), H * (0.28f + 0.07f * std::cos(t * 0.30f)),
                        W * 0.32f, H * 0.36f, d2d_rgb(236, 72, 153, 0.14f));

        std::lock_guard<std::mutex> lk(st.mu);
        const float pad = 20.0f;

        // 1. Header Glass Bar
        D2D1_RECT_F hdr = D2D1::RectF(pad, 16.0f, W - pad, 78.0f);
        draw_glass_card(hdr, 18.0f, true, true);
        draw_text("OPENFIR", D2D1::RectF(hdr.left + 24.0f, hdr.top + 17.0f, hdr.left + 135.0f, hdr.bottom), C_TEXT_PRI, tf_title);
        draw_text("v1.1 FROST", D2D1::RectF(hdr.left + 130.0f, hdr.top + 22.0f, hdr.left + 220.0f, hdr.bottom), C_CYAN, tf_bold);

        const char *tabs[4] = {"PUSH", "PULL", "SERVER", "AUDIT"};
        float tx = hdr.left + 240.0f;
        for (int i = 0; i < 4; ++i) {
            D2D1_RECT_F tr = D2D1::RectF(tx, hdr.top + 13.0f, tx + 92.0f, hdr.top + 49.0f);
            st.rc_tabs[i] = tr;
            bool act = (static_cast<int>(st.tab) == i);
            fill_gradient_rr(tr, 18.0f, act ? C_CYAN : C_GLASS_ELEV, act ? C_ACCENT_END : C_GLASS_ELEV);
            draw_text(tabs[i], D2D1::RectF(tr.left + 22.0f, tr.top + 9.0f, tr.right, tr.bottom), act ? C_VOID : C_TEXT_SEC, tf_bold);
            tx += 102.0f;
        }

        D2D1_COLOR_F bcol = C_TEXT_SEC;
        std::string btxt = "● IDLE";
        if (st.phase == "done") { bcol = C_MINT; btxt = "✓ MERKLE VERIFIED"; }
        else if (st.phase == "listening") { bcol = C_MINT; btxt = "◉ SERVER LIVE"; }
        else if (st.phase == "transferring" || st.phase == "handshake") { bcol = C_CYAN; btxt = "◈ STREAM ACTIVE"; }
        else if (st.phase == "error") { bcol = C_ROSE; btxt = "✕ ERROR"; }
        D2D1_RECT_F badge = D2D1::RectF(hdr.right - 178.0f, hdr.top + 16.0f, hdr.right - 16.0f, hdr.top + 46.0f);
        fill_gradient_rr(badge, 15.0f, C_GLASS_INPUT, C_GLASS_INPUT);
        draw_text(btxt, D2D1::RectF(badge.left + 14.0f, badge.top + 6.0f, badge.right, badge.bottom), bcol, tf_bold);

        // 2. Main Split Frosted Cards
        float body_y = 94.0f, body_b = H - 20.0f;
        float left_w = (W - 3.0f * pad) * 0.46f;
        D2D1_RECT_F lc = D2D1::RectF(pad, body_y, pad + left_w, body_b);
        D2D1_RECT_F rc = D2D1::RectF(pad * 2.0f + left_w, body_y, W - pad, body_b);
        draw_glass_card(lc, 20.0f, false, true);
        draw_glass_card(rc, 20.0f, false, false);

        for (auto &f : st.rc_fields) f = {};
        st.rc_keygen = {}; st.rc_browse = {}; st.rc_overwrite = {};
        for (auto &m : st.rc_modes) m = {};

        float fx = lc.left + 22.0f, fr = lc.right - 22.0f, fy = lc.top + 20.0f;
        std::string hdr_str = st.tab == Tab::Push ? "PUSH · HYBRID UPLOAD" :
                              st.tab == Tab::Pull ? "PULL · MERKLE DOWNLOAD" :
                              st.tab == Tab::Server ? "SERVER · DUAL-STACK TLS 1.3 + UDP" :
                              "AUDIT · 4-SUITE PROTOCOL VERIFICATION";
        draw_text(hdr_str, D2D1::RectF(fx, fy, fr, fy + 24.0f), C_CYAN, tf_bold);
        fy += 32.0f;

        auto draw_field = [&](int idx, const std::string &lbl, const std::string &val, float right_pad) {
            draw_text(lbl, D2D1::RectF(fx, fy, fr, fy + 18.0f), st.focus_field == idx ? C_CYAN : C_TEXT_SEC, tf_body);
            D2D1_RECT_F bx = D2D1::RectF(fx, fy + 22.0f, fr - right_pad, fy + 58.0f);
            st.rc_fields[idx] = bx;
            fill_gradient_rr(bx, 10.0f, C_GLASS_INPUT, C_GLASS_INPUT);
            ID2D1SolidColorBrush *rb = nullptr;
            if (SUCCEEDED(rt->CreateSolidColorBrush(st.focus_field == idx ? C_CYAN : d2d_rgb(255, 255, 255, 0.16f), &rb))) {
                rt->DrawRoundedRectangle(D2D1::RoundedRect(bx, 10.0f, 10.0f), rb, st.focus_field == idx ? 1.4f : 1.0f);
                rb->Release();
            }
            std::string shown = val.empty() ? "(click to type)" : val;
            if (st.focus_field == idx) shown += "|";
            draw_text(shown, D2D1::RectF(bx.left + 12.0f, bx.top + 9.0f, bx.right - 8.0f, bx.bottom),
                      val.empty() ? C_TEXT_MUTED : C_TEXT_MONO, tf_mono);
            fy += 66.0f;
        };

        if (st.tab == Tab::Push || st.tab == Tab::Pull) {
            draw_field(0, "SERVER ENDPOINT (host:port)", st.server_addr, 0.0f);
            float ky = fy + 22.0f;
            draw_field(1, "256-BIT SHARED SECRET", st.secret, 94.0f);
            st.rc_keygen = D2D1::RectF(fr - 86.0f, ky, fr, ky + 36.0f);
            fill_gradient_rr(st.rc_keygen, 10.0f, C_GLASS_ELEV, C_VIOLET);
            draw_text("KEYGEN", D2D1::RectF(st.rc_keygen.left + 16.0f, st.rc_keygen.top + 9.0f, st.rc_keygen.right, st.rc_keygen.bottom), C_TEXT_PRI, tf_bold);

            float by = fy + 22.0f;
            draw_field(2, st.tab == Tab::Push ? "LOCAL FILE / DIRECTORY" : "REMOTE FILE / DIRECTORY NAME",
                       st.file_path, st.tab == Tab::Push ? 94.0f : 0.0f);
            if (st.tab == Tab::Push) {
                st.rc_browse = D2D1::RectF(fr - 86.0f, by, fr, by + 36.0f);
                fill_gradient_rr(st.rc_browse, 10.0f, C_GLASS_ELEV, d2d_rgb(0, 180, 210, 0.75f));
                draw_text("BROWSE", D2D1::RectF(st.rc_browse.left + 14.0f, st.rc_browse.top + 9.0f, st.rc_browse.right, st.rc_browse.bottom), C_TEXT_PRI, tf_bold);
            } else {
                float dy = fy + 22.0f;
                draw_field(3, "LOCAL OUTPUT DIRECTORY", st.out_dir, 94.0f);
                st.rc_browse = D2D1::RectF(fr - 86.0f, dy, fr, dy + 36.0f);
                fill_gradient_rr(st.rc_browse, 10.0f, C_GLASS_ELEV, d2d_rgb(0, 180, 210, 0.75f));
                draw_text("BROWSE", D2D1::RectF(st.rc_browse.left + 14.0f, st.rc_browse.top + 9.0f, st.rc_browse.right, st.rc_browse.bottom), C_TEXT_PRI, tf_bold);
            }

            draw_text("TRANSPORT DATA PLANE", D2D1::RectF(fx, fy, fr, fy + 18.0f), C_TEXT_SEC, tf_body);
            const char *ml[3] = {"AUTO HYBRID", "UDP GSO", "TLS 1.3 TCP"};
            float mw = (fr - fx - 16.0f) / 3.0f;
            for (int i = 0; i < 3; ++i) {
                D2D1_RECT_F mr = D2D1::RectF(fx + i * (mw + 8.0f), fy + 22.0f, fx + i * (mw + 8.0f) + mw, fy + 56.0f);
                st.rc_modes[i] = mr;
                bool act = (st.transport_idx == i);
                fill_gradient_rr(mr, 10.0f, act ? C_CYAN : C_GLASS_INPUT, act ? C_ACCENT_END : C_GLASS_INPUT);
                draw_text(ml[i], D2D1::RectF(mr.left + 12.0f, mr.top + 8.0f, mr.right, mr.bottom), act ? C_VOID : C_TEXT_SEC, tf_bold);
            }
            fy += 68.0f;
            st.rc_overwrite = D2D1::RectF(fx, fy, fr, fy + 30.0f);
            fill_gradient_rr(D2D1::RectF(fx, fy + 4.0f, fx + 44.0f, fy + 24.0f), 10.0f,
                             st.overwrite ? C_MINT : C_GLASS_INPUT, st.overwrite ? C_CYAN : C_GLASS_INPUT);
            draw_text(std::string("Allow Overwrite: ") + (st.overwrite ? "ON" : "OFF") + "  ·  4 TLS Lanes  ·  1000 MiB/s",
                      D2D1::RectF(fx + 56.0f, fy + 4.0f, fr, fy + 28.0f), C_TEXT_SEC, tf_body);
        } else if (st.tab == Tab::Server) {
            draw_field(0, "DUAL-STACK LISTEN ADDR (:9900 / :443)", st.listen_addr, 0.0f);
            float dy = fy + 22.0f;
            draw_field(1, "STORAGE ROOT DIRECTORY", st.out_dir, 94.0f);
            st.rc_browse = D2D1::RectF(fr - 86.0f, dy, fr, dy + 36.0f);
            fill_gradient_rr(st.rc_browse, 10.0f, C_GLASS_ELEV, d2d_rgb(0, 180, 210, 0.75f));
            draw_text("BROWSE", D2D1::RectF(st.rc_browse.left + 14.0f, st.rc_browse.top + 9.0f, st.rc_browse.right, st.rc_browse.bottom), C_TEXT_PRI, tf_bold);

            float ky = fy + 22.0f;
            draw_field(2, "SERVER 256-BIT SECRET", st.secret, 94.0f);
            st.rc_keygen = D2D1::RectF(fr - 86.0f, ky, fr, ky + 36.0f);
            fill_gradient_rr(st.rc_keygen, 10.0f, C_GLASS_ELEV, C_VIOLET);
            draw_text("KEYGEN", D2D1::RectF(st.rc_keygen.left + 16.0f, st.rc_keygen.top + 9.0f, st.rc_keygen.right, st.rc_keygen.bottom), C_TEXT_PRI, tf_bold);

            draw_text(st.server_status, D2D1::RectF(fx, fy + 10.0f, fr, fy + 40.0f), st.server_handle ? C_MINT : C_TEXT_SEC, tf_body);
        } else {
            draw_text("Zero-Dependency In-Process Protocol Audit:", D2D1::RectF(fx, fy, fr, fy + 24.0f), C_TEXT_PRI, tf_bold);
            draw_text("• Suite 1: 4 MiB Hybrid Auto Push + Pull (DEFLATE/Zero/Raw)", D2D1::RectF(fx, fy + 34.0f, fr, fy + 58.0f), st.suite_idx >= 1 ? C_CYAN : C_TEXT_SEC, tf_body);
            draw_text("• Suite 2: 17B Shift-Resistant Rabin CDC Cross-Session CAS", D2D1::RectF(fx, fy + 62.0f, fr, fy + 86.0f), st.suite_idx >= 2 ? C_CYAN : C_TEXT_SEC, tf_body);
            draw_text("• Suite 3: 10% Burst-Loss Pure UDP + GF(256) RS FEC", D2D1::RectF(fx, fy + 90.0f, fr, fy + 114.0f), st.suite_idx >= 3 ? C_CYAN : C_TEXT_SEC, tf_body);
            draw_text("• Suite 4: ISP UDP Blackhole -> TLS 1.3 TCP Auto-Failover", D2D1::RectF(fx, fy + 118.0f, fr, fy + 142.0f), st.suite_idx >= 4 ? C_MINT : C_TEXT_SEC, tf_body);
            draw_text("100% Apache-2.0 clean-room Win32 + Direct2D · Zero third-party deps", D2D1::RectF(fx, fy + 162.0f, fr, fy + 186.0f), C_TEXT_MUTED, tf_body);
        }

        // Primary CTA Button
        st.rc_cta = D2D1::RectF(fx, lc.bottom - 62.0f, fr, lc.bottom - 18.0f);
        bool is_stop = (st.tab == Tab::Server && st.server_handle != 0) || (st.tab != Tab::Server && st.active_job != 0);
        fill_gradient_rr(st.rc_cta, 12.0f,
                         is_stop ? C_ROSE : (st.tab == Tab::Server ? C_MINT : C_CYAN),
                         is_stop ? C_MAGENTA : (st.tab == Tab::Server ? C_CYAN : C_ACCENT_END));
        std::string cta = st.tab == Tab::Server ? (st.server_handle ? "STOP DUAL-STACK SERVER" : "START DUAL-STACK SERVER") :
                          st.active_job ? "CANCEL ACTIVE TRANSFER" :
                          st.tab == Tab::Push ? "LAUNCH HYBRID PUSH" :
                          st.tab == Tab::Pull ? "LAUNCH MERKLE PULL" : "RUN 4-SUITE PROTOCOL AUDIT";
        draw_text(cta, D2D1::RectF(st.rc_cta.left + 28.0f, st.rc_cta.top + 12.0f, st.rc_cta.right, st.rc_cta.bottom), C_VOID, tf_bold);

        // 3. Right Frosted Telemetry Card
        float rx = rc.left + 22.0f, rr = rc.right - 22.0f, ry = rc.top + 20.0f;
        draw_text("LIVE TELEMETRY · ZERO-COPY ENGINE", D2D1::RectF(rx, ry, rr, ry + 24.0f), C_VIOLET, tf_bold);

        char pct_buf[128];
        std::snprintf(pct_buf, sizeof(pct_buf), "%.1f%%   ·   %s / %s   ·   %s",
                      st.percent, fmt_bytes(st.bytes_done).c_str(), fmt_bytes(st.total_bytes).c_str(), st.active_lane.c_str());
        draw_text(pct_buf, D2D1::RectF(rx, ry + 28.0f, rr, ry + 50.0f), C_TEXT_PRI, tf_bold);

        D2D1_RECT_F pb = D2D1::RectF(rx, ry + 54.0f, rr, ry + 68.0f);
        fill_gradient_rr(pb, 7.0f, C_GLASS_INPUT, C_GLASS_INPUT);
        float fw_bar = (pb.right - pb.left) * static_cast<float>(std::clamp(st.percent, 0.0, 100.0) / 100.0);
        if (fw_bar > 4.0f) fill_gradient_rr(D2D1::RectF(pb.left, pb.top, pb.left + fw_bar, pb.bottom), 7.0f, C_CYAN, C_ACCENT_END);

        // 4 Frosted KPI Micro-Tiles
        float ky = ry + 84.0f, tw = (rr - rx - 14.0f) * 0.5f;
        char k1[64], k2[64], k3[64], k4[64];
        std::snprintf(k1, sizeof(k1), "%.2f MiB/s", st.goodput_mbps);
        std::snprintf(k2, sizeof(k2), "UDP %s · TCP %s", fmt_bytes(static_cast<int64_t>(st.wire_udp)).c_str(),
                      fmt_bytes(static_cast<int64_t>(st.wire_tcp)).c_str());
        std::snprintf(k3, sizeof(k3), "CAS %u · Zero %u · Deflate %u", st.cas_blocks, st.zero_blocks, st.comp_blocks);
        std::snprintf(k4, sizeof(k4), "Rec %u · FO %u · %.1f ms", st.fec_recovered, st.failover_blocks, st.rtt_ms);

        struct Kpi { D2D1_RECT_F r; const char *lbl; const char *val; D2D1_COLOR_F c; };
        Kpi kpis[4] = {
            {D2D1::RectF(rx, ky, rx + tw, ky + 68.0f), "EFFECTIVE GOODPUT", k1, C_CYAN},
            {D2D1::RectF(rx + tw + 14.0f, ky, rr, ky + 68.0f), "HYBRID WIRE I/O", k2, C_TEXT_MONO},
            {D2D1::RectF(rx, ky + 80.0f, rx + tw, ky + 148.0f), "RABIN CDC CAS / DEDUP", k3, C_MINT},
            {D2D1::RectF(rx + tw + 14.0f, ky + 80.0f, rr, ky + 148.0f), "GF(256) RS FEC & RTT", k4,
             (st.fec_recovered || st.failover_blocks) ? C_AMBER : C_TEXT_PRI}
        };
        for (const auto &kp : kpis) {
            draw_glass_card(kp.r, 14.0f, true, false);
            draw_text(kp.lbl, D2D1::RectF(kp.r.left + 14.0f, kp.r.top + 10.0f, kp.r.right - 8.0f, kp.r.top + 28.0f), C_TEXT_SEC, tf_body);
            draw_text(kp.val, D2D1::RectF(kp.r.left + 14.0f, kp.r.top + 36.0f, kp.r.right - 8.0f, kp.r.bottom - 6.0f), kp.c, tf_bold);
        }

        // Real-Time Sparkline Card
        float sp_y = ky + 164.0f;
        float sp_b = std::max(sp_y + 90.0f, rc.bottom - 74.0f);
        D2D1_RECT_F sp_card = D2D1::RectF(rx, sp_y, rr, sp_b);
        draw_glass_card(sp_card, 14.0f, true, false);
        draw_text("REAL-TIME THROUGHPUT SPARKLINE (MiB/s)",
                  D2D1::RectF(sp_card.left + 14.0f, sp_card.top + 10.0f, sp_card.right - 10.0f, sp_card.top + 28.0f), C_TEXT_SEC, tf_body);
        draw_sparkline(D2D1::RectF(sp_card.left + 12.0f, sp_card.top + 30.0f, sp_card.right - 12.0f, sp_card.bottom - 10.0f), st.spark, 60);

        // Merkle Verification Strip
        D2D1_RECT_F mk = D2D1::RectF(rx, rc.bottom - 58.0f, rr, rc.bottom - 18.0f);
        fill_gradient_rr(mk, 10.0f, C_GLASS_INPUT, C_GLASS_INPUT);
        if (!st.merkle_hex.empty()) {
            draw_text("✓ MERKLE SHA-256: " + st.merkle_hex,
                      D2D1::RectF(mk.left + 14.0f, mk.top + 11.0f, mk.right - 10.0f, mk.bottom), C_MINT, tf_mono);
        } else {
            draw_text(st.message, D2D1::RectF(mk.left + 14.0f, mk.top + 11.0f, mk.right - 10.0f, mk.bottom),
                      st.phase == "error" ? C_ROSE : C_TEXT_SEC, tf_body);
        }

        if (rt->EndDraw() == D2DERR_RECREATE_TARGET) discard_rt();
    }

    void on_click(float x, float y) {
        for (int i = 0; i < 4; ++i) {
            if (pt_in(st.rc_tabs[i], x, y)) { st.tab = static_cast<Tab>(i); st.focus_field = 0; return; }
            if (pt_in(st.rc_fields[i], x, y)) { st.focus_field = i; return; }
        }
        if (pt_in(st.rc_keygen, x, y)) { do_keygen(st); return; }
        if (pt_in(st.rc_browse, x, y)) {
            bool folder = (st.tab == Tab::Server || st.tab == Tab::Pull);
            std::string picked = pick_file_or_folder(hwnd, folder);
            if (!picked.empty()) {
                std::lock_guard<std::mutex> lk(st.mu);
                if (folder) st.out_dir = picked;
                else st.file_path = picked;
            }
            return;
        }
        for (int i = 0; i < 3; ++i) {
            if (pt_in(st.rc_modes[i], x, y)) { st.transport_idx = i; return; }
        }
        if (pt_in(st.rc_overwrite, x, y)) { st.overwrite = !st.overwrite; return; }
        if (pt_in(st.rc_cta, x, y)) { trigger_cta(st); return; }
    }

    void on_char(wchar_t ch) {
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
        if (!fld) return;
        if (ch == 8 && !fld->empty()) { fld->pop_back(); }
        else if (ch == 22) { // Ctrl+V paste
            if (OpenClipboard(hwnd)) {
                HANDLE h = GetClipboardData(CF_UNICODETEXT);
                if (h) {
                    const wchar_t *p = static_cast<const wchar_t *>(GlobalLock(h));
                    if (p) {
                        std::string pasted = wide_to_utf8(p);
                        for (char c : pasted) if (static_cast<unsigned char>(c) >= 0x20) fld->push_back(c);
                        GlobalUnlock(h);
                    }
                }
                CloseClipboard();
            }
        } else if (ch >= 0x20 && ch < 0x7F) {
            fld->push_back(static_cast<char>(ch));
        }
    }
};

LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto *app = reinterpret_cast<FrostWindow *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
        case WM_CREATE: {
            auto *cs = reinterpret_cast<CREATESTRUCTW *>(lp);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            return 0;
        }
        case WM_SIZE:
            if (app && app->rt) app->rt->Resize(D2D1::SizeU(LOWORD(lp), HIWORD(lp)));
            return 0;
        case WM_TIMER:
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_PAINT:
            if (app) { app->render(); ValidateRect(hwnd, nullptr); }
            return 0;
        case WM_LBUTTONDOWN:
            if (app) app->on_click(static_cast<float>(LOWORD(lp)), static_cast<float>(HIWORD(lp)));
            return 0;
        case WM_CHAR:
            if (app) app->on_char(static_cast<wchar_t>(wp));
            return 0;
        case WM_KEYDOWN:
            if (app && wp == VK_TAB) app->st.focus_field = (app->st.focus_field + 1) % 4;
            if (app && wp == VK_F5) trigger_cta(app->st);
            return 0;
        case WM_DESTROY:
            if (app) {
                if (app->st.active_job && g_core.transfer_cancel) g_core.transfer_cancel(app->st.active_job);
                if (app->st.server_handle && g_core.server_stop) g_core.server_stop(app->st.server_handle);
                app->discard_rt();
            }
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

int run_smoke_test() {
    AppState st;
    do_keygen(st);
    uint64_t j = g_core.selftest_start(on_engine_event, &st);
    if (j == 0) return 1;
    {
        std::lock_guard<std::mutex> lk(st.mu);
        st.active_job = j;
    }
    bool done = false, ok = false;
    for (int i = 0; i < 300; ++i) {
        {
            std::lock_guard<std::mutex> lk(st.mu);
            if (st.phase == "done") { done = true; ok = true; }
            if (st.phase == "error") { done = true; ok = false; }
        }
        if (done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::printf("[Windows GUI SmokeTest] version=%s phase=%s merkle=%.16s...\n",
                g_core.version(), st.phase.c_str(), st.merkle_hex.c_str());
    return (ok && !st.merkle_hex.empty()) ? 0 : 2;
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR cmdLine, int showCmd) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (!g_core.load()) {
        MessageBoxW(nullptr, L"Failed to load openfir_core.dll", L"OpenFIR", MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    if (cmdLine && wcsstr(cmdLine, L"--smoke-test") != nullptr) {
        int rc = run_smoke_test();
        CoUninitialize();
        return rc;
    }

    FrostWindow app;
    app.init_factories();
    do_keygen(app.st);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"OpenFIRFrostWindow";
    RegisterClassExW(&wc);

    app.hwnd = CreateWindowExW(0, wc.lpszClassName, L"OpenFIR v1.1 — Obsidian Frost Hybrid Transport",
                               WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1100, 720,
                               nullptr, nullptr, hInst, &app);

    // Enable Windows 11 Immersive Dark Titlebar + Native DWM Acrylic Backdrop
    BOOL dark = TRUE;
    DwmSetWindowAttribute(app.hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof(dark));
    DWORD backdrop = 3 /*DWMSBT_TRANSIENTWINDOW Acrylic*/;
    DwmSetWindowAttribute(app.hwnd, 38 /*DWMWA_SYSTEMBACKDROP_TYPE*/, &backdrop, sizeof(backdrop));

    ShowWindow(app.hwnd, showCmd);
    SetTimer(app.hwnd, 1, 16, nullptr); // Smooth 60 FPS Web3 aurora + sparkline

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CoUninitialize();
    return 0;
}
