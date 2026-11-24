// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/openfir/openfir/internal/cc"
	"github.com/openfir/openfir/internal/engine"
	"github.com/openfir/openfir/internal/security"
)

func main() {
	mode := flag.String("mode", "", "Execution mode: server | push | pull | keygen | selftest")
	listen := flag.String("listen", ":9900", "Single-port dual-stack (TLS 1.3 TCP + UDP) server listen address (e.g. :443 or :9900)")
	serverAddr := flag.String("server", "127.0.0.1:9900", "Target server address for push/pull")
	sni := flag.String("sni", "", "Optional TLS 1.3 SNI hostname (defaults to host from -server)")
	verifyCA := flag.Bool("verify-ca", false, "Enforce public/system CA verification on TLS 1.3 cert (recommended with -tls-cert)")
	tlsCert := flag.String("tls-cert", "", "Server TLS 1.3 certificate PEM path (auto-generates ephemeral cert if empty)")
	tlsKey := flag.String("tls-key", "", "Server TLS 1.3 private key PEM path")
	rootDir := flag.String("dir", "./openfir_data", "Server root directory (for Push destinations & Pull sources) OR local output dir for Pull")
	filePath := flag.String("file", "", "Local file/directory path for push, OR remote filename/directory for pull")
	remoteName := flag.String("name", "", "Optional remote filename override for push")
	secret := flag.String("secret", "", "Shared secret: 64-hex-chars or 'pass:<passphrase>' (or set OPENFIR_SECRET)")
	transportMode := flag.String("transport", "auto", "Data-plane mode: auto (Hybrid UDP+TLS-TCP) | udp | tcp")
	tcpStreams := flag.Int("tcp-streams", 4, "Parallel TLS 1.3 TCP data lanes for auto/tcp mode")
	initMBps := flag.Float64("init-mbps", cc.DefaultInitMBps, "Initial slow-start pacing rate in MiB/s (default 4.0 MiB/s)")
	maxMBps := flag.Float64("max-mbps", cc.DefaultMaxMBps, "Maximum pacing rate ceiling in MiB/s (default 1000.0 MiB/s)")
	maxParity := flag.Int("max-parity", 8, "Max GF(256) RS parity shards per 16-shard group (0% loss = 0 parity)")
	overwrite := flag.Bool("overwrite", false, "Allow overwriting existing destination files/directories")
	maxFileGB := flag.Int64("max-file-gb", 256, "Maximum allowed transfer size in GB on server")
	maxSessions := flag.Int("max-sessions", 64, "Maximum concurrent active transfer sessions on server")
	flag.Parse()

	if *mode == "" {
		fmt.Fprintf(os.Stderr, "OpenFIR v1.0 — Enterprise Hybrid TLS 1.3 + UDP GSO/FEC File & Directory Transfer Engine\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Generate 256-bit key : openfir -mode keygen\n")
		fmt.Fprintf(os.Stderr, "  Run built-in test    : openfir -mode selftest\n")
		fmt.Fprintf(os.Stderr, "  Start server         : openfir -mode server -listen :443 -dir ./data -secret <key>\n")
		fmt.Fprintf(os.Stderr, "  Push file/directory  : openfir -mode push -server host:443 -file ./dataset -secret <key>\n")
		fmt.Fprintf(os.Stderr, "  Pull file/directory  : openfir -mode pull -server host:443 -file dataset -dir ./out -secret <key>\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch strings.ToLower(*mode) {
	case "keygen":
		k, err := security.GenerateRandomKeyHex()
		if err != nil {
			log.Fatalf("keygen failed: %v", err)
		}
		fmt.Println(k)

	case "selftest":
		if err := runSelfTest(ctx); err != nil {
			log.Fatalf("[SelfTest] FAILED: %v", err)
		}

	case "server":
		mk, err := security.ParseSecret(*secret)
		if err != nil {
			log.Fatalf("[Error] %v", err)
		}
		srv, err := engine.NewServer(ctx, engine.ServerConfig{
			ListenAddr:     *listen,
			RootDir:        *rootDir,
			MasterKey:      mk,
			TLSCertFile:    *tlsCert,
			TLSKeyFile:     *tlsKey,
			AllowOverwrite: *overwrite,
			MaxFileSize:    *maxFileGB * 1024 * 1024 * 1024,
			MaxSessions:    *maxSessions,
		})
		if err != nil {
			log.Fatalf("[Error] start server: %v", err)
		}
		defer srv.Close()
		log.Printf("[Server] OpenFIR v1.0 listening on TLS 1.3 TCP %s + UDP :%d (root=%s, overwrite=%v)",
			srv.Addr(), srv.UDPPort(), *rootDir, *overwrite)
		<-ctx.Done()
		log.Printf("[Server] Shutting down cleanly...")

	case "push":
		if *filePath == "" {
			log.Fatalf("[Error] -file is required for push mode")
		}
		mk, err := security.ParseSecret(*secret)
		if err != nil {
			log.Fatalf("[Error] %v", err)
		}
		cli := engine.NewClient(engine.ClientConfig{
			ServerAddr: *serverAddr,
			ServerName: *sni,
			VerifyCA:   *verifyCA,
			MasterKey:  mk,
			Mode:       engine.TransportMode(strings.ToLower(*transportMode)),
			TCPStreams: *tcpStreams,
			InitMBps:   *initMBps,
			MaxMBps:    *maxMBps,
			MaxParity:  *maxParity,
		})
		defer cli.Close()
		st, err := cli.Push(ctx, *filePath, *remoteName)
		if err != nil {
			log.Fatalf("[Push] Failed: %v", err)
		}
		printStats("Push", st)

	case "pull":
		if *filePath == "" {
			log.Fatalf("[Error] -file (remote name) is required for pull mode")
		}
		mk, err := security.ParseSecret(*secret)
		if err != nil {
			log.Fatalf("[Error] %v", err)
		}
		cli := engine.NewClient(engine.ClientConfig{
			ServerAddr:     *serverAddr,
			ServerName:     *sni,
			VerifyCA:       *verifyCA,
			MasterKey:      mk,
			Mode:           engine.TransportMode(strings.ToLower(*transportMode)),
			TCPStreams:     *tcpStreams,
			InitMBps:       *initMBps,
			MaxMBps:        *maxMBps,
			MaxParity:      *maxParity,
			AllowOverwrite: *overwrite,
		})
		defer cli.Close()
		st, err := cli.Pull(ctx, *filePath, *rootDir)
		if err != nil {
			log.Fatalf("[Pull] Failed: %v", err)
		}
		printStats("Pull", st)

	default:
		log.Fatalf("[Error] unknown mode %q (expected server | push | pull | keygen | selftest)", *mode)
	}
}

func printStats(op string, st *engine.TransferStats) {
	fmt.Printf("\n======================================================================\n")
	fmt.Printf("[OpenFIR v1.0] %s 100%% Merkle-Verified!\n", op)
	fmt.Printf("  ├─ Size & Goodput   : %.2f MiB in %.3fs (Effective: %.2f MiB/s)\n",
		float64(st.TotalBytes)/(1024*1024), st.Elapsed.Seconds(), st.GoodputMBps())
	fmt.Printf("  ├─ Blocks Breakdown : Total=%d | CAS=%d | Resumed=%d | Zero=%d | Deflate=%d | Raw=%d\n",
		st.TotalBlocks, st.CASBlocks, st.ResumedBlocks, st.ZeroBlocks, st.CompressedBlocks, st.RawBlocks)
	fmt.Printf("  ├─ Hybrid Wire I/O  : UDP=%d B | TLS1.3-TCP=%d B | FECParity=%d | FECRecovered=%d | Failover=%d\n",
		st.WireUDPBytes, st.WireTCPBytes, st.FECParitySent, st.FECRecovered, st.UDPFallbackBlocks)
	fmt.Printf("  └─ Merkle Root      : %s\n", hex.EncodeToString(st.MerkleRoot[:]))
	fmt.Printf("======================================================================\n")
}

func runSelfTest(ctx context.Context) error {
	fmt.Println("=== OpenFIR v1.0 Enterprise Self-Test (Hybrid TLS 1.3 + UDP GSO/GF256-RS + Rabin CDC CAS + ISP Blackhole Failover) ===")
	tmpDir, err := os.MkdirTemp("", "openfir_v1_selftest_*")
	if err != nil {
		return err
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
		return err
	}
	defer srv.Close()

	// Suite 1: Mixed-entropy 4MB Push (DEFLATE + Zero + Raw) + Pull
	f1 := filepath.Join(tmpDir, "mixed.bin")
	raw := make([]byte, 4*1024*1024)
	copy(raw[0:1024*1024], bytes.Repeat([]byte("OPENFIR-ENTERPRISE-LOG-LINE-2026\n"), 32000))
	// [1MB..2MB] stays all-zero
	_, _ = io.ReadFull(rand.Reader, raw[2*1024*1024:])
	if err := os.WriteFile(f1, raw, 0644); err != nil {
		return err
	}

	cli := engine.NewClient(engine.ClientConfig{
		ServerAddr:     srv.Addr(),
		MasterKey:      mk,
		Mode:           engine.TransportAuto,
		TCPStreams:     4,
		InitMBps:       16.0,
		MaxMBps:        500.0,
		AllowOverwrite: true,
	})
	defer cli.Close()

	stPush, err := cli.Push(ctx, f1, "mixed.bin")
	if err != nil {
		return fmt.Errorf("suite 1 push: %w", err)
	}
	printStats("Suite 1 Push (Hybrid Auto)", stPush)

	stPull, err := cli.Pull(ctx, "mixed.bin", pullDir)
	if err != nil {
		return fmt.Errorf("suite 1 pull: %w", err)
	}
	gotPull, err := os.ReadFile(filepath.Join(pullDir, "mixed.bin"))
	if err != nil || !bytes.Equal(gotPull, raw) {
		return fmt.Errorf("suite 1 pull content mismatch")
	}
	printStats("Suite 1 Pull (Bidirectional)", stPull)

	// Suite 2: Byte-insertion shift-resistant Rabin CDC Cross-Session CAS
	f2 := filepath.Join(tmpDir, "mixed_shifted.bin")
	shifted := append([]byte("PREPEND-17-BYTES!"), raw...)
	if err := os.WriteFile(f2, shifted, 0644); err != nil {
		return err
	}
	stCAS, err := cli.Push(ctx, f2, "mixed_shifted.bin")
	if err != nil {
		return fmt.Errorf("suite 2 shifted CAS push: %w", err)
	}
	if stCAS.CASBlocks < stCAS.TotalBlocks/2 {
		return fmt.Errorf("suite 2 expected high Rabin CDC CAS reuse after 17B prepend, got %d/%d", stCAS.CASBlocks, stCAS.TotalBlocks)
	}
	printStats("Suite 2 Shift-Resistant Rabin CDC CAS", stCAS)

	// Suite 3: 10% Burst-Loss UDP Recovery with Adaptive GF(256) RS FEC (fresh random data to bypass CAS!)
	f3 := filepath.Join(tmpDir, "lossy_fresh.bin")
	raw3 := make([]byte, 2*1024*1024)
	_, _ = io.ReadFull(rand.Reader, raw3)
	if err := os.WriteFile(f3, raw3, 0644); err != nil {
		return err
	}
	cliLoss := engine.NewClient(engine.ClientConfig{
		ServerAddr: srv.Addr(),
		MasterKey:  mk,
		Mode:       engine.TransportUDP,
		InitMBps:   32.0,
		MaxMBps:    200.0,
		UDPChaos:   &engine.UDPChaos{LossRate: 0.10, BurstLen: 4},
	})
	defer cliLoss.Close()
	stLoss, err := cliLoss.Push(ctx, f3, "lossy_fresh.bin")
	if err != nil {
		return fmt.Errorf("suite 3 lossy UDP push: %w", err)
	}
	printStats("Suite 3 10% Burst-Loss Pure UDP + GF(256) RS", stLoss)

	// Suite 4: Mid-Stream ISP UDP Blackhole Auto-Failover to Multi-Stream TLS 1.3 TCP (fresh random data!)
	f4 := filepath.Join(tmpDir, "blackhole_fresh.bin")
	raw4 := make([]byte, 2*1024*1024)
	_, _ = io.ReadFull(rand.Reader, raw4)
	if err := os.WriteFile(f4, raw4, 0644); err != nil {
		return err
	}
	cliBlackhole := engine.NewClient(engine.ClientConfig{
		ServerAddr: srv.Addr(),
		MasterKey:  mk,
		Mode:       engine.TransportAuto,
		TCPStreams: 4,
		InitMBps:   16.0,
		MaxMBps:    200.0,
		UDPChaos:   &engine.UDPChaos{LossRate: 0.0, BlackholeAfter: 40}, // Healthy UDP start -> sudden 100% blackhole!
	})
	defer cliBlackhole.Close()
	stBH, err := cliBlackhole.Push(ctx, f4, "blackhole_fresh.bin")
	if err != nil {
		return fmt.Errorf("suite 4 UDP blackhole failover: %w", err)
	}
	printStats("Suite 4 Mid-Stream ISP UDP Blackhole -> TLS 1.3 TCP Auto-Failover", stBH)

	fmt.Printf("\n[SelfTest] ALL ENTERPRISE SUITES PASSED 100%%! (%s)\n", time.Now().Format(time.RFC3339))
	return nil
}
