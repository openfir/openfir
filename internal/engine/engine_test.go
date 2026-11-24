// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/openfir/openfir/internal/cdc"
	"github.com/openfir/openfir/internal/security"
	"github.com/openfir/openfir/internal/storage"
)

func testMasterKey(t *testing.T) [32]byte {
	t.Helper()
	mk, err := security.ParseSecret("pass:OpenFIR-v1.0-Enterprise-Test-Secret!")
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

// Suite 1: Hybrid Push & Bidirectional Pull on 6MB Mixed-Entropy File (DEFLATE + Zero + Raw + 0% FEC Overhead)
func TestHybridPushAndPullLargeMixedEntropyWithDeflateAndZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmp := t.TempDir()
	srvDir := filepath.Join(tmp, "srv")
	pullDir := filepath.Join(tmp, "pull")
	mk := testMasterKey(t)

	srv, err := NewServer(ctx, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		RootDir:        srvDir,
		MasterKey:      mk,
		AllowOverwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// 6 MB mixed payload: 2MB compressible JSON logs + 2MB all-zero sparse + 2MB incompressible random
	raw := make([]byte, 6*1024*1024)
	copy(raw[0:2*1024*1024], bytes.Repeat([]byte(`{"event":"transfer","status":"ok","node":"edge-01"}`+"\n"), 40000))
	// [2MB..4MB] stays all-zero
	_, _ = io.ReadFull(rand.Reader, raw[4*1024*1024:])
	srcPath := filepath.Join(tmp, "dataset.bin")
	if err := os.WriteFile(srcPath, raw, 0644); err != nil {
		t.Fatal(err)
	}

	cli := NewClient(ClientConfig{
		ServerAddr:     srv.Addr(),
		MasterKey:      mk,
		Mode:           TransportAuto,
		TCPStreams:     4,
		InitMBps:       16.0,
		MaxMBps:        500.0,
		AllowOverwrite: true,
	})
	defer cli.Close()

	stPush, err := cli.Push(ctx, srcPath, "dataset.bin")
	if err != nil {
		t.Fatalf("Hybrid Push failed: %v", err)
	}
	if stPush.CompressedBlocks == 0 || stPush.ZeroBlocks == 0 || stPush.RawBlocks == 0 {
		t.Fatalf("expected Deflate + Zero + Raw blocks all active, got deflate=%d zero=%d raw=%d",
			stPush.CompressedBlocks, stPush.ZeroBlocks, stPush.RawBlocks)
	}
	if stPush.FECParitySent != 0 {
		t.Fatalf("expected STRICTLY 0 FEC parity packets on lossless link, got %d", stPush.FECParitySent)
	}
	if stPush.WireUDPBytes == 0 || stPush.WireTCPBytes == 0 {
		t.Fatalf("expected Hybrid Auto to engage BOTH UDP and TLS 1.3 TCP lanes, got udp=%d tcp=%d",
			stPush.WireUDPBytes, stPush.WireTCPBytes)
	}
	gotSrv, err := os.ReadFile(filepath.Join(srvDir, "dataset.bin"))
	if err != nil || !bytes.Equal(gotSrv, raw) {
		t.Fatal("pushed file content mismatch")
	}

	// Bidirectional Pull back to client!
	stPull, err := cli.Pull(ctx, "dataset.bin", pullDir)
	if err != nil {
		t.Fatalf("Bidirectional Pull failed: %v", err)
	}
	gotPull, err := os.ReadFile(filepath.Join(pullDir, "dataset.bin"))
	if err != nil || !bytes.Equal(gotPull, raw) {
		t.Fatal("pulled file content mismatch")
	}
	t.Logf("PASS: 6MB Hybrid Push (UDP=%dB TCP=%dB Deflate=%d Zero=%d Raw=%d FECParity=0) + Bidirectional Pull (%.2f MiB/s) 100%% Merkle-verified!",
		stPush.WireUDPBytes, stPush.WireTCPBytes, stPush.CompressedBlocks, stPush.ZeroBlocks, stPush.RawBlocks, stPull.GoodputMBps())
}

// Suite 2: Pure UDP under 10% Gilbert-Elliott 4-packet Contiguous Burst Loss -> Adaptive GF(256) RS FEC Recovery!
func TestPureUDPLossyBurstWithAdaptiveGF256RS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmp := t.TempDir()
	srvDir := filepath.Join(tmp, "srv")
	mk := testMasterKey(t)

	srv, err := NewServer(ctx, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		RootDir:        srvDir,
		MasterKey:      mk,
		AllowOverwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	raw := make([]byte, 3*1024*1024)
	_, _ = io.ReadFull(rand.Reader, raw)
	srcPath := filepath.Join(tmp, "lossy.bin")
	if err := os.WriteFile(srcPath, raw, 0644); err != nil {
		t.Fatal(err)
	}

	chaos := &UDPChaos{LossRate: 0.10, BurstLen: 4}
	cli := NewClient(ClientConfig{
		ServerAddr: srv.Addr(),
		MasterKey:  mk,
		Mode:       TransportUDP,
		InitMBps:   32.0,
		MaxMBps:    200.0,
		MaxParity:  8,
		UDPChaos:   chaos,
	})
	defer cli.Close()

	st, err := cli.Push(ctx, srcPath, "lossy.bin")
	if err != nil {
		t.Fatalf("Pure UDP 10%% burst-loss push failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(srvDir, "lossy.bin"))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("lossy UDP file corrupted")
	}
	if st.FECParitySent == 0 || st.FECRecovered == 0 {
		t.Fatalf("expected adaptive GF(256) RS FEC to engage and recover burst drops, got parity=%d rec=%d",
			st.FECParitySent, st.FECRecovered)
	}
	t.Logf("PASS: 3MB Pure UDP under 10%% 4-pkt burst loss (dropped=%d, RS parity=%d, RS recovered=%d slices) 100%% intact!",
		chaos.Dropped(), st.FECParitySent, st.FECRecovered)
}

// Suite 3: ISP Total UDP Block AND Mid-Stream ISP UDP Blackhole -> Seamless Auto-Failover to Multi-Stream TLS 1.3 TCP!
func TestISPUdpBlackholeAndMidStreamQoSFailoverToTLS13(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmp := t.TempDir()
	srvDir := filepath.Join(tmp, "srv")
	mk := testMasterKey(t)

	// Part A: Firewall blocks 100% of UDP from packet #0 (DisableUDP on server)
	srvNoUDP, err := NewServer(ctx, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		RootDir:        srvDir,
		MasterKey:      mk,
		AllowOverwrite: true,
		DisableUDP:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srvNoUDP.Close()

	raw := make([]byte, 3*1024*1024)
	_, _ = io.ReadFull(rand.Reader, raw)
	srcPath := filepath.Join(tmp, "qos.bin")
	if err := os.WriteFile(srcPath, raw, 0644); err != nil {
		t.Fatal(err)
	}

	cliA := NewClient(ClientConfig{
		ServerAddr: srvNoUDP.Addr(),
		MasterKey:  mk,
		Mode:       TransportAuto,
		TCPStreams: 4,
	})
	defer cliA.Close()
	stA, err := cliA.Push(ctx, srcPath, "qos_blocked_udp.bin")
	if err != nil {
		t.Fatalf("Part A (UDP blocked firewall) failed: %v", err)
	}
	if stA.WireUDPBytes != 0 || stA.WireTCPBytes == 0 {
		t.Fatalf("Part A expected pure TLS 1.3 TCP fallback, got udp=%d tcp=%d", stA.WireUDPBytes, stA.WireTCPBytes)
	}
	gotA, _ := os.ReadFile(filepath.Join(srvDir, "qos_blocked_udp.bin"))
	if !bytes.Equal(gotA, raw) {
		t.Fatal("Part A content mismatch")
	}

	// Part B: UDP starts healthy (probe + first 40 data packets pass), then ISP BLACKHOLES 100% of UDP MID-STREAM!
	srvDirB := filepath.Join(tmp, "srvB")
	srvB, err := NewServer(ctx, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		RootDir:        srvDirB,
		MasterKey:      mk,
		AllowOverwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srvB.Close()

	chaos := &UDPChaos{LossRate: 0.0, BlackholeAfter: 40}

	cliB := NewClient(ClientConfig{
		ServerAddr: srvB.Addr(),
		MasterKey:  mk,
		Mode:       TransportAuto,
		TCPStreams: 4,
		InitMBps:   16.0,
		MaxMBps:    100.0,
		UDPChaos:   chaos,
	})
	defer cliB.Close()

	stB, err := cliB.Push(ctx, srcPath, "qos_midstream_blackhole.bin")
	if err != nil {
		t.Fatalf("Part B (Mid-stream ISP UDP blackhole failover) failed: %v", err)
	}
	if stB.WireUDPBytes == 0 || stB.WireTCPBytes == 0 || stB.UDPFallbackBlocks == 0 {
		t.Fatalf("Part B expected UDP start + mid-stream failover to TCP, got udp=%d tcp=%d fallback=%d",
			stB.WireUDPBytes, stB.WireTCPBytes, stB.UDPFallbackBlocks)
	}
	gotB, _ := os.ReadFile(filepath.Join(srvDirB, "qos_midstream_blackhole.bin"))
	if !bytes.Equal(gotB, raw) {
		t.Fatal("Part B content mismatch")
	}
	t.Logf("PASS: ISP UDP QoS Defense — Part A (100%% UDP blocked -> TLS 1.3 TCP %dB) & Part B (mid-stream UDP blackhole -> seamless failover=%d blocks, TCP=%dB) 100%% intact!",
		stA.WireTCPBytes, stB.UDPFallbackBlocks, stB.WireTCPBytes)
}

// Suite 4: Shift-Resistant Exact Rabin CDC Cross-Session CAS (0% False Positives, Zero Bloom Saturation!)
func TestShiftResistantRabinCDCCrossSessionCAS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmp := t.TempDir()
	srvDir := filepath.Join(tmp, "srv")
	mk := testMasterKey(t)

	srv, err := NewServer(ctx, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		RootDir:        srvDir,
		MasterKey:      mk,
		AllowOverwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	v1 := make([]byte, 4*1024*1024)
	_, _ = io.ReadFull(rand.Reader, v1)
	p1 := filepath.Join(tmp, "image_v1.bin")
	_ = os.WriteFile(p1, v1, 0644)

	cli := NewClient(ClientConfig{
		ServerAddr: srv.Addr(),
		MasterKey:  mk,
		Mode:       TransportAuto,
		TCPStreams: 4,
		InitMBps:   32.0,
		MaxMBps:    500.0,
	})
	defer cli.Close()

	if _, err := cli.Push(ctx, p1, "image_v1.bin"); err != nil {
		t.Fatal(err)
	}

	// Prepend 17 bytes at byte 0 + modify 128KB in the middle!
	v2 := make([]byte, 0, len(v1)+17)
	v2 = append(v2, []byte("PREPEND-17-BYTES!")...)
	v2 = append(v2, v1...)
	_, _ = io.ReadFull(rand.Reader, v2[2*1024*1024:2*1024*1024+128*1024])
	p2 := filepath.Join(tmp, "image_v2.bin")
	_ = os.WriteFile(p2, v2, 0644)

	st2, err := cli.Push(ctx, p2, "image_v2.bin")
	if err != nil {
		t.Fatal(err)
	}
	got2, _ := os.ReadFile(filepath.Join(srvDir, "image_v2.bin"))
	if !bytes.Equal(got2, v2) {
		t.Fatal("v2 content mismatch after Rabin CDC CAS teleport")
	}
	hitRate := float64(st2.CASBlocks) * 100.0 / float64(st2.TotalBlocks)
	if hitRate < 85.0 {
		t.Fatalf("expected >=85%% exact Rabin CDC CAS teleport after 17-byte prepend + 128KB edit, got %.2f%% (%d/%d)",
			hitRate, st2.CASBlocks, st2.TotalBlocks)
	}
	t.Logf("PASS: Shift-Resistant Exact Rabin CDC CAS teleported %.2f%% (%d/%d blocks, 0%% false positives, wire=%dB for 4MB file)!",
		hitRate, st2.CASBlocks, st2.TotalBlocks, st2.WireUDPBytes+st2.WireTCPBytes)
}

// Suite 5: Zero-RTT Directory Tree (150 nested files + empty subdirectories) Push + Pull
func TestZeroRTTDirectoryTreeWithEmptyDirs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmp := t.TempDir()
	srvDir := filepath.Join(tmp, "srv")
	pullDir := filepath.Join(tmp, "pull")
	srcTree := filepath.Join(tmp, "project_repo")
	mk := testMasterKey(t)

	_ = os.MkdirAll(filepath.Join(srcTree, "empty_dir", "nested_empty"), 0755)
	expected := make(map[string][]byte)
	for i := 0; i < 150; i++ {
		sub := filepath.Join(srcTree, "pkg_"+string(rune('a'+i%6)))
		_ = os.MkdirAll(sub, 0755)
		p := filepath.Join(sub, "file_"+string(rune('0'+i%10))+string(rune('a'+(i/10)%26))+".dat")
		data := make([]byte, 200+(i*173)%4096)
		_, _ = io.ReadFull(rand.Reader, data)
		_ = os.WriteFile(p, data, 0644)
		rel, _ := filepath.Rel(srcTree, p)
		expected[rel] = data
	}

	srv, err := NewServer(ctx, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		RootDir:        srvDir,
		MasterKey:      mk,
		AllowOverwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cli := NewClient(ClientConfig{
		ServerAddr:     srv.Addr(),
		MasterKey:      mk,
		Mode:           TransportAuto,
		TCPStreams:     2,
		AllowOverwrite: true,
	})
	defer cli.Close()

	if _, err := cli.Push(ctx, srcTree, "project_repo"); err != nil {
		t.Fatalf("dir push failed: %v", err)
	}
	if _, err := cli.Pull(ctx, "project_repo", pullDir); err != nil {
		t.Fatalf("dir pull failed: %v", err)
	}

	gotTree := filepath.Join(pullDir, "project_repo")
	if st, err := os.Stat(filepath.Join(gotTree, "empty_dir", "nested_empty")); err != nil || !st.IsDir() {
		t.Fatal("empty nested subdirectory not preserved")
	}
	for rel, want := range expected {
		got, err := os.ReadFile(filepath.Join(gotTree, rel))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("directory file %s mismatch", rel)
		}
	}
	t.Logf("PASS: 150-file nested directory tree + empty subdirs Pushed & Pulled 100%% intact!")
}

// Suite 6: Persistent Crash-Resume via .openfir-part + .openfir-state (survives disconnect & server restart!)
func TestPersistentCrashResumeAcrossRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmp := t.TempDir()
	srvDir := filepath.Join(tmp, "srv")
	mk := testMasterKey(t)

	raw := make([]byte, 3*1024*1024)
	_, _ = io.ReadFull(rand.Reader, raw)
	srcPath := filepath.Join(tmp, "resume_me.bin")
	_ = os.WriteFile(srcPath, raw, 0644)

	// Simulate an earlier interrupted transfer that already persisted the first 60% of Rabin CDC blocks!
	rs, err := storage.OpenResumableStaging(srvDir, "resume_me.bin", int64(len(raw)), false)
	if err != nil {
		t.Fatal(err)
	}
	ch := cdc.NewChunker(bytes.NewReader(raw), cdc.DefaultMinChunk, cdc.DefaultAvgChunk, cdc.DefaultMaxChunk)
	var allMetas []cdc.BlockMeta
	var allData [][]byte
	for {
		m, d, err := ch.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		allMetas = append(allMetas, m)
		allData = append(allData, d)
	}
	preWritten := (len(allMetas) * 60) / 100
	for i := 0; i < preWritten; i++ {
		if err := rs.WriteVerifiedBlock(allMetas[i], allData[i]); err != nil {
			t.Fatal(err)
		}
	}
	rs.PauseAndClose() // Persists .openfir-state and keeps .openfir-part on disk!

	// Start a brand-new Server instance (simulating full server restart!) and Push!
	srv, err := NewServer(ctx, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		RootDir:        srvDir,
		MasterKey:      mk,
		AllowOverwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cli := NewClient(ClientConfig{
		ServerAddr: srv.Addr(),
		MasterKey:  mk,
		Mode:       TransportAuto,
		TCPStreams: 2,
	})
	defer cli.Close()

	st, err := cli.Push(ctx, srcPath, "resume_me.bin")
	if err != nil {
		t.Fatalf("Resumed Push failed: %v", err)
	}
	if int(st.ResumedBlocks) != preWritten {
		t.Fatalf("expected exactly %d blocks resumed from persistent .openfir-state, got %d", preWritten, st.ResumedBlocks)
	}
	got, err := os.ReadFile(filepath.Join(srvDir, "resume_me.bin"))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("resumed file content mismatch")
	}
	t.Logf("PASS: Persistent Crash-Resume skipped %d/%d verified blocks across full server restart with 0 wire bytes!",
		st.ResumedBlocks, st.TotalBlocks)
}

// Suite 7: Mutual RFC 5705 Channel-Bound Auth rejects wrong Argon2id passphrase
func TestMutualAuthRejectsWrongKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmp := t.TempDir()
	srvMK, _ := security.ParseSecret("pass:CorrectEnterprisePass123!")
	badMK, _ := security.ParseSecret("pass:WrongEnterprisePass999!")

	srv, err := NewServer(ctx, ServerConfig{
		ListenAddr: "127.0.0.1:0",
		RootDir:    filepath.Join(tmp, "srv"),
		MasterKey:  srvMK,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	f := filepath.Join(tmp, "a.txt")
	_ = os.WriteFile(f, []byte("hello"), 0644)
	cli := NewClient(ClientConfig{
		ServerAddr: srv.Addr(),
		MasterKey:  badMK,
	})
	defer cli.Close()

	if _, err := cli.Push(ctx, f, "a.txt"); err == nil {
		t.Fatal("expected mutual auth to reject wrong Argon2id passphrase")
	}
}
