// SPDX-License-Identifier: Apache-2.0
//
// Shared Swift C-ABI Bridge to OpenFIRCore.xcframework (macOS 13+ & iOS 15+).
// Zero third-party dependencies — strictly Foundation + Combine + OpenFIRCore.

import Foundation
import Combine
import OpenFIRCore

public enum OpenFIRTab: Int, CaseIterable, Identifiable {
    case push = 0
    case pull = 1
    case server = 2
    case audit = 3

    public var id: Int { rawValue }
    public var title: String {
        switch self {
        case .push: return "PUSH"
        case .pull: return "PULL"
        case .server: return "SERVER"
        case .audit: return "AUDIT"
        }
    }
}

public struct OpenFIRTelemetry: Decodable {
    public let job_id: UInt64?
    public let op: String?
    public let phase: String?
    public let message: String?
    public let bytes_done: Int64?
    public let total_bytes: Int64?
    public let percent: Double?
    public let goodput_mbps: Double?
    public let instant_mbps: Double?
    public let rtt_ms: Double?
    public let active_lane: String?
    public let wire_udp_bytes: UInt64?
    public let wire_tcp_bytes: UInt64?
    public let total_blocks: UInt32?
    public let cas_blocks: UInt32?
    public let zero_blocks: UInt32?
    public let compressed_blocks: UInt32?
    public let fec_recovered: UInt32?
    public let udp_fallback_blocks: UInt32?
    public let merkle_root_hex: String?
    public let suite_index: Int?
}

private func openfirEventTrampoline(handle: UInt64, jsonPtr: UnsafePointer<CChar>?, ctx: UnsafeMutableRawPointer?) {
    guard let ctx = ctx, let jsonPtr = jsonPtr else { return }
    let jsonStr = String(cString: jsonPtr)
    let bridge = Unmanaged<OpenFIRBridge>.fromOpaque(ctx).takeUnretainedValue()
    DispatchQueue.main.async {
        bridge.handleEvent(handle: handle, json: jsonStr)
    }
}

@MainActor
public final class OpenFIRBridge: ObservableObject {
    @Published public var selectedTab: OpenFIRTab = .push
    @Published public var serverAddr: String = "127.0.0.1:9900"
    @Published public var listenAddr: String = ":9900"
    @Published public var secret: String = ""
    @Published public var filePath: String = ""
    @Published public var outDir: String = ""
    @Published public var transportMode: String = "auto"
    @Published public var tcpStreams: Int = 4
    @Published public var maxMBps: Int = 1000
    @Published public var overwrite: Bool = true

    @Published public var activeJob: UInt64 = 0 {
        didSet { rawActiveJob = activeJob }
    }
    @Published public var serverHandle: UInt64 = 0 {
        didSet { rawServerHandle = serverHandle }
    }
    nonisolated(unsafe) private var rawActiveJob: UInt64 = 0
    nonisolated(unsafe) private var rawServerHandle: UInt64 = 0
    @Published public var serverStatus: String = "Server standby — ready to bind TLS 1.3 + UDP"

    @Published public var phase: String = "idle"
    @Published public var message: String = "Ready · Hybrid TLS 1.3 + UDP GSO/GF(256) RS + Rabin CDC"
    @Published public var activeLane: String = "STANDBY"
    @Published public var merkleHex: String = ""
    @Published public var percent: Double = 0
    @Published public var goodputMBps: Double = 0
    @Published public var rttMs: Double = 0
    @Published public var bytesDone: Int64 = 0
    @Published public var totalBytes: Int64 = 0
    @Published public var wireUDP: UInt64 = 0
    @Published public var wireTCP: UInt64 = 0
    @Published public var casBlocks: UInt32 = 0
    @Published public var zeroBlocks: UInt32 = 0
    @Published public var compBlocks: UInt32 = 0
    @Published public var fecRecovered: UInt32 = 0
    @Published public var failoverBlocks: UInt32 = 0
    @Published public var suiteIdx: Int = 0
    @Published public var sparkline: [Double] = Array(repeating: 0, count: 60)

    public var versionString: String {
        guard let p = openfir_version() else { return "OpenFIR v1.1" }
        return String(cString: p)
    }

    public init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        self.outDir = docs?.appendingPathComponent("OpenFIR").path ?? "./openfir_data"
        try? FileManager.default.createDirectory(atPath: self.outDir, withIntermediateDirectories: true)
        generateKey()
    }

    deinit {
        if rawActiveJob != 0 { openfir_transfer_cancel(rawActiveJob) }
        if rawServerHandle != 0 { openfir_server_stop(rawServerHandle) }
    }

    public func generateKey() {
        var buf = [CChar](repeating: 0, count: 80)
        let n = openfir_keygen(&buf, buf.count)
        if n == 64 {
            secret = String(cString: buf)
            message = "Generated fresh 256-bit cryptographically secure key"
        }
    }

    public func triggerPrimaryAction() {
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        if selectedTab == .server {
            if serverHandle != 0 {
                let h = serverHandle
                serverHandle = 0
                phase = "idle"
                serverStatus = "Server stopped"
                message = "Dual-stack server stopped cleanly"
                openfir_server_stop(h)
                return
            }
            let payload: [String: Any] = [
                "listen": listenAddr,
                "dir": outDir,
                "secret": secret,
                "overwrite": overwrite,
                "max_sessions": 64
            ]
            guard let data = try? JSONSerialization.data(withJSONObject: payload),
                  let str = String(data: data, encoding: .utf8) else { return }
            let h = str.withCString { openfir_server_start($0, openfirEventTrampoline, ctx) }
            serverHandle = h
            return
        }

        if activeJob != 0 {
            let j = activeJob
            activeJob = 0
            phase = "idle"
            message = "Transfer cancelled"
            openfir_transfer_cancel(j)
            return
        }

        resetTelemetry()
        if selectedTab == .audit {
            phase = "transferring"
            message = "Running 4-Suite Enterprise Protocol Audit..."
            activeJob = openfir_selftest_start(openfirEventTrampoline, ctx)
            return
        }

        let payload: [String: Any] = [
            "op": selectedTab == .push ? "push" : "pull",
            "server": serverAddr,
            "secret": secret,
            "file": filePath,
            "dir": outDir,
            "transport": transportMode,
            "tcp_streams": tcpStreams,
            "max_mbps": maxMBps,
            "overwrite": overwrite
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let str = String(data: data, encoding: .utf8) else { return }
        phase = "handshake"
        let j = str.withCString { openfir_transfer_start($0, openfirEventTrampoline, ctx) }
        if j != 0 { activeJob = j }
    }

    private func resetTelemetry() {
        percent = 0; goodputMBps = 0; rttMs = 0
        bytesDone = 0; totalBytes = 0; wireUDP = 0; wireTCP = 0
        casBlocks = 0; zeroBlocks = 0; compBlocks = 0
        fecRecovered = 0; failoverBlocks = 0; suiteIdx = 0
        merkleHex = ""
        sparkline = Array(repeating: 0, count: 60)
    }

    fileprivate func handleEvent(handle: UInt64, json: String) {
        guard let data = json.data(using: .utf8),
              let ev = try? JSONDecoder().decode(OpenFIRTelemetry.self, from: data) else { return }

        if ev.op == "server" {
            if ev.phase == "listening" {
                serverStatus = ev.message ?? "Listening"
                phase = "listening"
                message = serverStatus
            } else if ev.phase == "error" {
                serverHandle = 0
                serverStatus = "ERROR: \(ev.message ?? "unknown")"
                phase = "error"
                message = ev.message ?? "Server error"
            }
            return
        }

        if handle != 0 && activeJob != 0 && handle != activeJob { return }

        if let p = ev.phase, !p.isEmpty { phase = p }
        if let m = ev.message, !m.isEmpty { message = m }
        if let l = ev.active_lane, !l.isEmpty { activeLane = l }
        if let mk = ev.merkle_root_hex, !mk.isEmpty { merkleHex = mk }

        if let v = ev.percent { percent = v }
        if let v = ev.goodput_mbps { goodputMBps = v }
        if let v = ev.rtt_ms { rttMs = v }
        if let v = ev.bytes_done { bytesDone = v }
        if let v = ev.total_bytes { totalBytes = v }
        if let v = ev.wire_udp_bytes { wireUDP = v }
        if let v = ev.wire_tcp_bytes { wireTCP = v }
        if let v = ev.cas_blocks { casBlocks = v }
        if let v = ev.zero_blocks { zeroBlocks = v }
        if let v = ev.compressed_blocks { compBlocks = v }
        if let v = ev.fec_recovered { fecRecovered = v }
        if let v = ev.udp_fallback_blocks { failoverBlocks = v }
        if let v = ev.suite_index { suiteIdx = v }

        if ev.phase == "transferring" || ev.phase == "done" {
            let sample = (ev.instant_mbps ?? 0) > 0.01 ? (ev.instant_mbps ?? 0) : goodputMBps
            sparkline.removeFirst()
            sparkline.append(max(0, sample))
        }
        if ev.phase == "done" || ev.phase == "error" {
            activeJob = 0
        }
    }

    public static func formatBytes(_ b: Int64) -> String {
        if b >= 1_073_741_824 { return String(format: "%.2f GiB", Double(b) / 1_073_741_824.0) }
        if b >= 1_048_576 { return String(format: "%.2f MiB", Double(b) / 1_048_576.0) }
        if b >= 1024 { return String(format: "%.1f KiB", Double(b) / 1024.0) }
        return "\(b) B"
    }
}
