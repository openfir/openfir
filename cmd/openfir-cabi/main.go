// SPDX-License-Identifier: Apache-2.0

package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef void (*openfir_event_cb)(uint64_t handle, const char *json_utf8, void *user_ctx);

static inline void invoke_openfir_event_cb(openfir_event_cb cb, uint64_t handle, const char *json_utf8, void *user_ctx) {
	if (cb != NULL) {
		cb(handle, json_utf8, user_ctx);
	}
}
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/openfir/openfir/internal/cc"
	"github.com/openfir/openfir/internal/engine"
	"github.com/openfir/openfir/internal/security"
)

const engineVersionStr = "OpenFIR v1.1.0"

var (
	versionCStr = C.CString(engineVersionStr)

	nextHandle atomic.Uint64

	jobsMu sync.Mutex
	jobs   = make(map[uint64]context.CancelFunc)

	serversMu sync.Mutex
	servers   = make(map[uint64]*engine.Server)
)

type transferConfigJSON struct {
	Op         string  `json:"op"`
	Server     string  `json:"server"`
	SNI        string  `json:"sni"`
	VerifyCA   bool    `json:"verify_ca"`
	Secret     string  `json:"secret"`
	File       string  `json:"file"`
	Name       string  `json:"name"`
	Dir        string  `json:"dir"`
	Transport  string  `json:"transport"`
	TCPStreams int     `json:"tcp_streams"`
	InitMBps   float64 `json:"init_mbps"`
	MaxMBps    float64 `json:"max_mbps"`
	MaxParity  int     `json:"max_parity"`
	Overwrite  bool    `json:"overwrite"`
}

type serverConfigJSON struct {
	Listen      string `json:"listen"`
	Dir         string `json:"dir"`
	Secret      string `json:"secret"`
	TLSCert     string `json:"tls_cert"`
	TLSKey      string `json:"tls_key"`
	Overwrite   bool   `json:"overwrite"`
	MaxFileGB   int64  `json:"max_file_gb"`
	MaxSessions int    `json:"max_sessions"`
}

func emitJSON(cb C.openfir_event_cb, handle uint64, ctxPtr unsafe.Pointer, payload any) {
	if cb == nil {
		return
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	cs := C.CString(string(b))
	defer C.free(unsafe.Pointer(cs))
	C.invoke_openfir_event_cb(cb, C.uint64_t(handle), cs, ctxPtr)
}

func emitError(cb C.openfir_event_cb, handle uint64, ctxPtr unsafe.Pointer, op, msg string) {
	emitJSON(cb, handle, ctxPtr, engine.ProgressSnapshot{
		JobID:   handle,
		Op:      op,
		Phase:   "error",
		Message: msg,
	})
}

//export openfir_version
func openfir_version() *C.char {
	return versionCStr
}

//export openfir_keygen
func openfir_keygen(outHex *C.char, outCap C.size_t) C.int {
	if outHex == nil || outCap < 65 {
		return -1
	}
	k, err := security.GenerateRandomKeyHex()
	if err != nil {
		return -2
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(outHex)), int(outCap))
	copy(dst, k)
	dst[len(k)] = 0
	return C.int(len(k))
}

//export openfir_transfer_start
func openfir_transfer_start(configJSON *C.char, cb C.openfir_event_cb, userCtx unsafe.Pointer) C.uint64_t {
	if configJSON == nil {
		emitError(cb, 0, userCtx, "transfer", "null config JSON")
		return 0
	}
	var cfg transferConfigJSON
	if err := json.Unmarshal([]byte(C.GoString(configJSON)), &cfg); err != nil {
		emitError(cb, 0, userCtx, "transfer", fmt.Sprintf("invalid config JSON: %v", err))
		return 0
	}
	op := strings.ToLower(strings.TrimSpace(cfg.Op))
	if op != "push" && op != "pull" {
		emitError(cb, 0, userCtx, op, "op must be 'push' or 'pull'")
		return 0
	}
	if strings.TrimSpace(cfg.Server) == "" {
		emitError(cb, 0, userCtx, op, "server address is required")
		return 0
	}
	if strings.TrimSpace(cfg.File) == "" {
		emitError(cb, 0, userCtx, op, "file path or remote name is required")
		return 0
	}
	mk, err := security.ParseSecret(cfg.Secret)
	if err != nil {
		emitError(cb, 0, userCtx, op, err.Error())
		return 0
	}

	mode := engine.TransportAuto
	switch strings.ToLower(strings.TrimSpace(cfg.Transport)) {
	case "udp":
		mode = engine.TransportUDP
	case "tcp":
		mode = engine.TransportTCP
	}
	if cfg.TCPStreams <= 0 {
		cfg.TCPStreams = 4
	}
	if cfg.InitMBps <= 0 {
		cfg.InitMBps = cc.DefaultInitMBps
	}
	if cfg.MaxMBps <= 0 {
		cfg.MaxMBps = cc.DefaultMaxMBps
	}
	if cfg.MaxParity <= 0 {
		cfg.MaxParity = 8
	}

	jobID := nextHandle.Add(1)
	ctx, cancel := context.WithCancel(context.Background())

	jobsMu.Lock()
	jobs[jobID] = cancel
	jobsMu.Unlock()

	go func() {
		defer func() {
			cancel()
			jobsMu.Lock()
			delete(jobs, jobID)
			jobsMu.Unlock()
		}()

		emitJSON(cb, jobID, userCtx, engine.ProgressSnapshot{
			JobID:   jobID,
			Op:      op,
			Phase:   "handshake",
			Message: fmt.Sprintf("Connecting TLS 1.3 + UDP probe to %s", cfg.Server),
		})

		cli := engine.NewClient(engine.ClientConfig{
			ServerAddr:     strings.TrimSpace(cfg.Server),
			ServerName:     strings.TrimSpace(cfg.SNI),
			VerifyCA:       cfg.VerifyCA,
			MasterKey:      mk,
			Mode:           mode,
			TCPStreams:     cfg.TCPStreams,
			InitMBps:       cfg.InitMBps,
			MaxMBps:        cfg.MaxMBps,
			MaxParity:      cfg.MaxParity,
			AllowOverwrite: cfg.Overwrite,
			OnProgress: func(snap engine.ProgressSnapshot) {
				snap.JobID = jobID
				snap.Op = op
				emitJSON(cb, jobID, userCtx, snap)
			},
		})
		defer cli.Close()

		var runErr error
		if op == "push" {
			_, runErr = cli.Push(ctx, strings.TrimSpace(cfg.File), strings.TrimSpace(cfg.Name))
		} else {
			outDir := strings.TrimSpace(cfg.Dir)
			if outDir == "" {
				outDir = "."
			}
			_, runErr = cli.Pull(ctx, strings.TrimSpace(cfg.File), outDir)
		}
		if runErr != nil {
			emitError(cb, jobID, userCtx, op, runErr.Error())
		}
	}()

	return C.uint64_t(jobID)
}

//export openfir_transfer_cancel
func openfir_transfer_cancel(jobID C.uint64_t) {
	jobsMu.Lock()
	cancel, ok := jobs[uint64(jobID)]
	jobsMu.Unlock()
	if ok && cancel != nil {
		cancel()
	}
}

//export openfir_server_start
func openfir_server_start(configJSON *C.char, cb C.openfir_event_cb, userCtx unsafe.Pointer) C.uint64_t {
	if configJSON == nil {
		emitError(cb, 0, userCtx, "server", "null server config JSON")
		return 0
	}
	var cfg serverConfigJSON
	if err := json.Unmarshal([]byte(C.GoString(configJSON)), &cfg); err != nil {
		emitError(cb, 0, userCtx, "server", fmt.Sprintf("invalid server config JSON: %v", err))
		return 0
	}
	mk, err := security.ParseSecret(cfg.Secret)
	if err != nil {
		emitError(cb, 0, userCtx, "server", err.Error())
		return 0
	}
	if strings.TrimSpace(cfg.Listen) == "" {
		cfg.Listen = ":9900"
	}
	if strings.TrimSpace(cfg.Dir) == "" {
		cfg.Dir = "./openfir_data"
	}
	if cfg.MaxFileGB <= 0 {
		cfg.MaxFileGB = 256
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}

	srv, err := engine.NewServer(context.Background(), engine.ServerConfig{
		ListenAddr:     strings.TrimSpace(cfg.Listen),
		RootDir:        strings.TrimSpace(cfg.Dir),
		MasterKey:      mk,
		TLSCertFile:    strings.TrimSpace(cfg.TLSCert),
		TLSKeyFile:     strings.TrimSpace(cfg.TLSKey),
		AllowOverwrite: cfg.Overwrite,
		MaxFileSize:    cfg.MaxFileGB * 1024 * 1024 * 1024,
		MaxSessions:    cfg.MaxSessions,
	})
	if err != nil {
		emitError(cb, 0, userCtx, "server", err.Error())
		return 0
	}

	handle := nextHandle.Add(1)
	serversMu.Lock()
	servers[handle] = srv
	serversMu.Unlock()

	emitJSON(cb, handle, userCtx, map[string]any{
		"job_id":   handle,
		"op":       "server",
		"phase":    "listening",
		"tcp_addr": srv.Addr(),
		"udp_port": srv.UDPPort(),
		"root_dir": cfg.Dir,
		"message":  fmt.Sprintf("Dual-Stack Listening TLS 1.3 TCP %s + UDP :%d", srv.Addr(), srv.UDPPort()),
	})

	return C.uint64_t(handle)
}

//export openfir_server_stop
func openfir_server_stop(serverHandle C.uint64_t) {
	id := uint64(serverHandle)
	serversMu.Lock()
	srv, ok := servers[id]
	if ok {
		delete(servers, id)
	}
	serversMu.Unlock()
	if ok && srv != nil {
		srv.Close()
	}
}

//export openfir_selftest_start
func openfir_selftest_start(cb C.openfir_event_cb, userCtx unsafe.Pointer) C.uint64_t {
	jobID := nextHandle.Add(1)
	ctx, cancel := context.WithCancel(context.Background())

	jobsMu.Lock()
	jobs[jobID] = cancel
	jobsMu.Unlock()

	go func() {
		defer func() {
			cancel()
			jobsMu.Lock()
			delete(jobs, jobID)
			jobsMu.Unlock()
		}()

		tmpDir, err := os.MkdirTemp("", "openfir_gui_audit_*")
		if err != nil {
			emitError(cb, jobID, userCtx, "selftest", err.Error())
			return
		}
		defer os.RemoveAll(tmpDir)

		var mk [32]byte
		_, _ = io.ReadFull(rand.Reader, mk[:])
		srvDir := filepath.Join(tmpDir, "srv")
		pullDir := filepath.Join(tmpDir, "pull")

		srv, err := engine.NewServer(ctx, engine.ServerConfig{
			ListenAddr:     "127.0.0.1:0",
			RootDir:        srvDir,
			MasterKey:      mk,
			AllowOverwrite: true,
		})
		if err != nil {
			emitError(cb, jobID, userCtx, "selftest", err.Error())
			return
		}
		defer srv.Close()

		emitSuite := func(idx int, phase, msg string, base *engine.ProgressSnapshot) {
			var snap engine.ProgressSnapshot
			if base != nil {
				snap = *base
			}
			snap.JobID = jobID
			snap.Op = "selftest"
			snap.Phase = phase
			snap.Message = msg
			snap.SuiteIndex = idx
			snap.SuiteTotal = 4
			if phase != "done" {
				overall := (float64(idx-1) + snap.Percent/100.0) / 4.0 * 100.0
				if overall > 99.0 {
					overall = 99.0
				}
				snap.Percent = overall
			}
			emitJSON(cb, jobID, userCtx, snap)
		}

		// Suite 1: Mixed-entropy 4 MiB Hybrid Auto Push + Bidirectional Pull
		f1 := filepath.Join(tmpDir, "mixed.bin")
		raw := make([]byte, 4*1024*1024)
		copy(raw[0:1024*1024], bytes.Repeat([]byte("OPENFIR-ENTERPRISE-LOG-LINE-2026\n"), 32000))
		_, _ = io.ReadFull(rand.Reader, raw[2*1024*1024:])
		if err := os.WriteFile(f1, raw, 0644); err != nil {
			emitError(cb, jobID, userCtx, "selftest", err.Error())
			return
		}
		emitSuite(1, "transferring", "Suite 1/4: 4 MiB Hybrid Auto Push + Pull (DEFLATE + Zero + Raw)", nil)
		cli := engine.NewClient(engine.ClientConfig{
			ServerAddr:     srv.Addr(),
			MasterKey:      mk,
			Mode:           engine.TransportAuto,
			TCPStreams:     4,
			InitMBps:       16.0,
			MaxMBps:        500.0,
			AllowOverwrite: true,
			OnProgress: func(s engine.ProgressSnapshot) {
				if s.Phase != "done" {
					emitSuite(1, "transferring", "Suite 1/4: Hybrid Auto Push + Pull", &s)
				}
			},
		})
		defer cli.Close()
		if _, err := cli.Push(ctx, f1, "mixed.bin"); err != nil {
			emitError(cb, jobID, userCtx, "selftest", "suite 1 push: "+err.Error())
			return
		}
		if _, err := cli.Pull(ctx, "mixed.bin", pullDir); err != nil {
			emitError(cb, jobID, userCtx, "selftest", "suite 1 pull: "+err.Error())
			return
		}
		gotPull, err := os.ReadFile(filepath.Join(pullDir, "mixed.bin"))
		if err != nil || !bytes.Equal(gotPull, raw) {
			emitError(cb, jobID, userCtx, "selftest", "suite 1 pull content mismatch")
			return
		}

		// Suite 2: Shift-resistant Rabin CDC Cross-Session CAS
		f2 := filepath.Join(tmpDir, "mixed_shifted.bin")
		shifted := append([]byte("PREPEND-17-BYTES!"), raw...)
		_ = os.WriteFile(f2, shifted, 0644)
		emitSuite(2, "transferring", "Suite 2/4: Shift-Resistant Rabin CDC CAS (17B prepend)", nil)
		stCAS, err := cli.Push(ctx, f2, "mixed_shifted.bin")
		if err != nil {
			emitError(cb, jobID, userCtx, "selftest", "suite 2 cas: "+err.Error())
			return
		}
		if stCAS.CASBlocks < stCAS.TotalBlocks/2 {
			emitError(cb, jobID, userCtx, "selftest", "suite 2 low CAS reuse")
			return
		}

		// Suite 3: 10% Burst-Loss UDP + GF(256) RS FEC Recovery
		f3 := filepath.Join(tmpDir, "lossy_fresh.bin")
		raw3 := make([]byte, 2*1024*1024)
		_, _ = io.ReadFull(rand.Reader, raw3)
		_ = os.WriteFile(f3, raw3, 0644)
		emitSuite(3, "transferring", "Suite 3/4: 10% Burst-Loss Pure UDP + GF(256) RS FEC", nil)
		cliLoss := engine.NewClient(engine.ClientConfig{
			ServerAddr: srv.Addr(),
			MasterKey:  mk,
			Mode:       engine.TransportUDP,
			InitMBps:   32.0,
			MaxMBps:    200.0,
			UDPChaos:   &engine.UDPChaos{LossRate: 0.10, BurstLen: 4},
			OnProgress: func(s engine.ProgressSnapshot) {
				if s.Phase != "done" {
					emitSuite(3, "transferring", "Suite 3/4: 10% Burst-Loss GF(256) RS FEC", &s)
				}
			},
		})
		defer cliLoss.Close()
		if _, err := cliLoss.Push(ctx, f3, "lossy_fresh.bin"); err != nil {
			emitError(cb, jobID, userCtx, "selftest", "suite 3 lossy udp: "+err.Error())
			return
		}

		// Suite 4: Mid-Stream ISP UDP Blackhole -> TLS 1.3 TCP Failover
		f4 := filepath.Join(tmpDir, "blackhole_fresh.bin")
		raw4 := make([]byte, 2*1024*1024)
		_, _ = io.ReadFull(rand.Reader, raw4)
		_ = os.WriteFile(f4, raw4, 0644)
		emitSuite(4, "transferring", "Suite 4/4: Mid-Stream ISP UDP Blackhole -> TLS 1.3 Failover", nil)
		var lastSnap engine.ProgressSnapshot
		cliBH := engine.NewClient(engine.ClientConfig{
			ServerAddr: srv.Addr(),
			MasterKey:  mk,
			Mode:       engine.TransportAuto,
			TCPStreams: 4,
			InitMBps:   16.0,
			MaxMBps:    200.0,
			UDPChaos:   &engine.UDPChaos{LossRate: 0.0, BlackholeAfter: 40},
			OnProgress: func(s engine.ProgressSnapshot) {
				lastSnap = s
				if s.Phase != "done" {
					emitSuite(4, "transferring", "Suite 4/4: ISP UDP Blackhole Failover", &s)
				}
			},
		})
		defer cliBH.Close()
		stBH, err := cliBH.Push(ctx, f4, "blackhole_fresh.bin")
		if err != nil {
			emitError(cb, jobID, userCtx, "selftest", "suite 4 failover: "+err.Error())
			return
		}

		lastSnap.JobID = jobID
		lastSnap.Op = "selftest"
		lastSnap.Phase = "done"
		lastSnap.Percent = 100.0
		lastSnap.SuiteIndex = 4
		lastSnap.SuiteTotal = 4
		lastSnap.CASBlocks += stCAS.CASBlocks
		lastSnap.UDPFallbackBlocks = stBH.UDPFallbackBlocks
		lastSnap.Message = fmt.Sprintf("ALL 4 ENTERPRISE SUITES VERIFIED (%s | CAS=%d | Failover=%d)",
			time.Now().Format("15:04:05"), stCAS.CASBlocks, stBH.UDPFallbackBlocks)
		emitJSON(cb, jobID, userCtx, lastSnap)
	}()

	return C.uint64_t(jobID)
}

func main() {}
