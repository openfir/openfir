/* SPDX-License-Identifier: Apache-2.0
 *
 * OpenFIR Core C ABI (include/openfir.h)
 * Zero third-party dependencies — bridges native C11/C++20/Swift/Kotlin UIs
 * directly into the OpenFIR Hybrid TLS 1.3 + UDP GSO/GF(256) RS + Rabin CDC engine.
 */

#ifndef OPENFIR_CABI_H
#define OPENFIR_CABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Telemetry / lifecycle JSON callback invoked from background engine goroutines.
 * `json_utf8` is NUL-terminated and valid only for the duration of the callback;
 * native UIs must copy the string before returning or dispatching to the main thread.
 */
typedef void (*openfir_event_cb)(uint64_t handle, const char *json_utf8, void *user_ctx);

/* Returns static NUL-terminated engine version string (e.g. "OpenFIR v1.1.0"). */
const char *openfir_version(void);

/* Generates a cryptographically secure 256-bit shared secret (64 lowercase hex chars + NUL).
 * `out_cap` must be >= 65. Returns 64 on success, or negative error code.
 */
int openfir_keygen(char *out_hex, size_t out_cap);

/* Starts an async Push or Pull transfer from JSON config:
 * {
 *   "op": "push" | "pull",
 *   "server": "127.0.0.1:9900",
 *   "sni": "",
 *   "verify_ca": false,
 *   "secret": "<64-hex or pass:...>",
 *   "file": "/path/to/local_or_remote",
 *   "name": "",
 *   "dir": "./out",
 *   "transport": "auto" | "udp" | "tcp",
 *   "tcp_streams": 4,
 *   "init_mbps": 4.0,
 *   "max_mbps": 1000.0,
 *   "max_parity": 8,
 *   "overwrite": true
 * }
 * Returns non-zero job handle on success, or 0 on invalid JSON / config error (error detail
 * is delivered synchronously via `cb` if provided).
 */
uint64_t openfir_transfer_start(const char *config_json, openfir_event_cb cb, void *user_ctx);

/* Requests immediate graceful cancellation of an active transfer or selftest job. */
void openfir_transfer_cancel(uint64_t job_id);

/* Starts an embedded dual-stack TLS 1.3 TCP + UDP OpenFIR server from JSON config:
 * {
 *   "listen": ":9900",
 *   "dir": "./openfir_data",
 *   "secret": "<64-hex or pass:...>",
 *   "tls_cert": "",
 *   "tls_key": "",
 *   "overwrite": true,
 *   "max_file_gb": 256,
 *   "max_sessions": 64
 * }
 * Returns non-zero server handle on success (and emits a "listening" event containing
 * actual bound tcp_addr and udp_port), or 0 on failure.
 */
uint64_t openfir_server_start(const char *config_json, openfir_event_cb cb, void *user_ctx);

/* Stops an active embedded OpenFIR server and releases all sockets. */
void openfir_server_stop(uint64_t server_handle);

/* Runs the full 4-suite OpenFIR enterprise verification audit asynchronously and
 * streams real-time per-suite progress & Merkle results via `cb`.
 * Returns non-zero job handle on success.
 */
uint64_t openfir_selftest_start(openfir_event_cb cb, void *user_ctx);

#ifdef __cplusplus
}
#endif

#endif /* OPENFIR_CABI_H */
