// SPDX-License-Identifier: Apache-2.0

package engine

import "encoding/hex"

// ProgressSnapshot carries lock-free real-time transfer telemetry for native GUIs and TUIs.
type ProgressSnapshot struct {
	JobID             uint64  `json:"job_id,omitempty"`
	Op                string  `json:"op"`                // "push" | "pull" | "selftest" | "server"
	Phase             string  `json:"phase"`             // "handshake" | "transferring" | "merkle_verify" | "done" | "error" | "listening" | "stopped"
	Message           string  `json:"message,omitempty"` // Human-readable status or error detail
	BytesDone         int64   `json:"bytes_done"`
	TotalBytes        int64   `json:"total_bytes"`
	Percent           float64 `json:"percent"`
	GoodputMBps       float64 `json:"goodput_mbps"`
	InstantMBps       float64 `json:"instant_mbps"`
	PacingMBps        float64 `json:"pacing_mbps"`
	RTTMs             float64 `json:"rtt_ms"`
	ActiveLane        string  `json:"active_lane"` // "HYBRID" | "UDP-GSO" | "TLS1.3-TCP" | "FAILOVER-TCP"
	WireUDPBytes      uint64  `json:"wire_udp_bytes"`
	WireTCPBytes      uint64  `json:"wire_tcp_bytes"`
	TotalBlocks       uint32  `json:"total_blocks"`
	CASBlocks         uint32  `json:"cas_blocks"`
	ResumedBlocks     uint32  `json:"resumed_blocks"`
	ZeroBlocks        uint32  `json:"zero_blocks"`
	CompressedBlocks  uint32  `json:"compressed_blocks"`
	RawBlocks         uint32  `json:"raw_blocks"`
	FECParitySent     uint64  `json:"fec_parity_sent"`
	FECRecovered      uint32  `json:"fec_recovered"`
	UDPFallbackBlocks uint32  `json:"udp_fallback_blocks"`
	ExtractedItems    int     `json:"extracted_items"`
	ElapsedMs         int64   `json:"elapsed_ms"`
	MerkleRootHex     string  `json:"merkle_root_hex,omitempty"`
	SuiteIndex        int     `json:"suite_index,omitempty"`
	SuiteTotal        int     `json:"suite_total,omitempty"`
}

func snapshotFromFinalStats(op string, st *TransferStats) ProgressSnapshot {
	if st == nil {
		return ProgressSnapshot{Op: op, Phase: "done", Percent: 100.0}
	}
	lane := "TLS1.3-TCP"
	if st.WireUDPBytes > 0 && st.WireTCPBytes > 0 {
		if st.UDPFallbackBlocks > 0 {
			lane = "FAILOVER-TCP"
		} else {
			lane = "HYBRID"
		}
	} else if st.WireUDPBytes > 0 {
		lane = "UDP-GSO"
	}
	return ProgressSnapshot{
		Op:                op,
		Phase:             "done",
		BytesDone:         st.TotalBytes,
		TotalBytes:        st.TotalBytes,
		Percent:           100.0,
		GoodputMBps:       st.GoodputMBps(),
		InstantMBps:       st.GoodputMBps(),
		ActiveLane:        lane,
		WireUDPBytes:      st.WireUDPBytes,
		WireTCPBytes:      st.WireTCPBytes,
		TotalBlocks:       st.TotalBlocks,
		CASBlocks:         st.CASBlocks,
		ResumedBlocks:     st.ResumedBlocks,
		ZeroBlocks:        st.ZeroBlocks,
		CompressedBlocks:  st.CompressedBlocks,
		RawBlocks:         st.RawBlocks,
		FECParitySent:     st.FECParitySent,
		FECRecovered:      st.FECRecovered,
		UDPFallbackBlocks: st.UDPFallbackBlocks,
		ExtractedItems:    st.ExtractedItems,
		ElapsedMs:         st.Elapsed.Milliseconds(),
		MerkleRootHex:     hex.EncodeToString(st.MerkleRoot[:]),
	}
}
