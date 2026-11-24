// SPDX-License-Identifier: Apache-2.0
//
// Unified "Obsidian Frost x Neon Aurora" Modern Web3 Glassmorphism UI for
// macOS 13+ (AppKit NSVisualEffectView Vibrancy) and iOS 15.0+ (SwiftUI ultraThinMaterial).
// 100% original Apache-2.0 code — ZERO third-party dependencies.

import SwiftUI
import UniformTypeIdentifiers
#if os(macOS)
import AppKit
#elseif os(iOS)
import UIKit
#endif

public enum FrostPalette {
    public static let bgVoid     = Color(red: 7/255,   green: 9/255,   blue: 19/255)
    public static let cyan       = Color(red: 0/255,   green: 240/255, blue: 255/255)
    public static let violet     = Color(red: 139/255, green: 92/255,  blue: 246/255)
    public static let accentEnd  = Color(red: 124/255, green: 58/255,  blue: 237/255)
    public static let magenta    = Color(red: 236/255, green: 72/255,  blue: 153/255)
    public static let glassTint  = Color(red: 17/255,  green: 23/255,  blue: 42/255).opacity(0.62)
    public static let glassElev  = Color(red: 26/255,  green: 35/255,  blue: 62/255).opacity(0.74)
    public static let glassInput = Color(red: 10/255,  green: 15/255,  blue: 29/255).opacity(0.76)
    public static let mint       = Color(red: 16/255,  green: 249/255, blue: 160/255)
    public static let amber      = Color(red: 255/255, green: 176/255, blue: 32/255)
    public static let rose       = Color(red: 255/255, green: 77/255,  blue: 141/255)
    public static let textPri    = Color(red: 248/255, green: 250/255, blue: 252/255)
    public static let textSec    = Color(red: 148/255, green: 163/255, blue: 184/255)
    public static let textMono   = Color(red: 125/255, green: 211/255, blue: 252/255)

    public static let primaryGradient = LinearGradient(
        colors: [cyan, accentEnd],
        startPoint: .leading,
        endPoint: .trailing
    )
}

#if os(macOS)
public struct MacVibrancyView: NSViewRepresentable {
    public var material: NSVisualEffectView.Material = .hudWindow
    public func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.material = material
        v.blendingMode = .withinWindow
        v.state = .active
        return v
    }
    public func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
    }
}
#endif

public struct AuroraPlasmaBackdrop: View {
    public init() {}

    public var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0)) { timeline in
            let t = timeline.date.timeIntervalSinceReferenceDate
            Canvas { ctx, size in
                drawAurora(in: &ctx, size: size, t: t)
            }
        }
        .ignoresSafeArea()
    }

    private func drawAurora(in ctx: inout GraphicsContext, size: CGSize, t: Double) {
        ctx.fill(Path(CGRect(origin: .zero, size: size)), with: .color(FrostPalette.bgVoid))
        let maxDim: CGFloat = max(size.width, size.height)

        let p1 = CGPoint(
            x: size.width * CGFloat(0.20 + 0.06 * sin(t * 0.45)),
            y: size.height * CGFloat(0.22 + 0.06 * cos(t * 0.37))
        )
        let p2 = CGPoint(
            x: size.width * CGFloat(0.80 + 0.07 * cos(t * 0.32)),
            y: size.height * CGFloat(0.78 + 0.06 * sin(t * 0.41))
        )
        let p3 = CGPoint(
            x: size.width * CGFloat(0.60 + 0.08 * sin(t * 0.27 + 1.2)),
            y: size.height * CGFloat(0.26 + 0.07 * cos(t * 0.30))
        )

        drawOrb(in: &ctx, center: p1, radius: maxDim * 0.46, color: FrostPalette.cyan.opacity(0.28))
        drawOrb(in: &ctx, center: p2, radius: maxDim * 0.50, color: FrostPalette.violet.opacity(0.32))
        drawOrb(in: &ctx, center: p3, radius: maxDim * 0.34, color: FrostPalette.magenta.opacity(0.16))
    }

    private func drawOrb(in ctx: inout GraphicsContext, center: CGPoint, radius: CGFloat, color: Color) {
        let rect = CGRect(x: center.x - radius, y: center.y - radius, width: radius * 2, height: radius * 2)
        let grad = Gradient(colors: [color, color.opacity(0)])
        ctx.fill(Path(ellipseIn: rect), with: .radialGradient(grad, center: center, startRadius: 0, endRadius: radius))
    }
}

public struct FrostedGlassCard<Content: View>: View {
    public let elevated: Bool
    public let activeRim: Bool
    public let radius: CGFloat
    public let content: () -> Content

    public init(elevated: Bool = false, activeRim: Bool = false, radius: CGFloat = 18, @ViewBuilder content: @escaping () -> Content) {
        self.elevated = elevated
        self.activeRim = activeRim
        self.radius = radius
        self.content = content
    }

    public var body: some View {
        ZStack {
            #if os(macOS)
            MacVibrancyView(material: elevated ? .popover : .hudWindow)
                .opacity(0.55)
            #else
            Rectangle()
                .fill(.ultraThinMaterial)
                .opacity(0.55)
            #endif
            (elevated ? FrostPalette.glassElev : FrostPalette.glassTint)
            LinearGradient(
                colors: [Color.white.opacity(0.08), Color.clear],
                startPoint: .top,
                endPoint: .center
            )
            content()
                .padding(16)
        }
        .clipShape(RoundedRectangle(cornerRadius: radius, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: radius, style: .continuous)
                .strokeBorder(
                    LinearGradient(
                        colors: activeRim
                            ? [FrostPalette.cyan.opacity(0.75), FrostPalette.violet.opacity(0.65)]
                            : [Color.white.opacity(0.20), FrostPalette.violet.opacity(0.14)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: activeRim ? 1.3 : 1.0
                )
        )
    }
}

public struct NeonSparklineChart: View {
    public let samples: [Double]

    public var body: some View {
        Canvas { ctx, size in
            guard samples.count >= 2 else { return }
            let maxV = max(samples.max() ?? 1.0, 1.0)
            var stroke = Path()
            var area = Path()
            area.move(to: CGPoint(x: 0, y: size.height))
            for i in samples.indices {
                let x = size.width * CGFloat(i) / CGFloat(samples.count - 1)
                let y = size.height - 4 - CGFloat(min(max(samples[i] / maxV, 0), 1)) * (size.height - 10)
                if i == 0 {
                    stroke.move(to: CGPoint(x: x, y: y))
                    area.addLine(to: CGPoint(x: x, y: y))
                } else {
                    stroke.addLine(to: CGPoint(x: x, y: y))
                    area.addLine(to: CGPoint(x: x, y: y))
                }
            }
            area.addLine(to: CGPoint(x: size.width, y: size.height))
            area.closeSubpath()

            ctx.fill(area, with: .linearGradient(
                Gradient(colors: [FrostPalette.cyan.opacity(0.32), FrostPalette.violet.opacity(0.02)]),
                startPoint: .zero,
                endPoint: CGPoint(x: 0, y: size.height)
            ))
            ctx.stroke(stroke, with: .linearGradient(
                Gradient(colors: [FrostPalette.cyan, FrostPalette.violet]),
                startPoint: .zero,
                endPoint: CGPoint(x: size.width, y: 0)
            ), lineWidth: 2.2)
        }
    }
}

public struct OpenFIRMainView: View {
    @ObservedObject public var vm: OpenFIRBridge
    @State private var showFileImporter = false
    @State private var pickFolderMode = false

    public init(vm: OpenFIRBridge) {
        self.vm = vm
    }

    public var body: some View {
        ZStack {
            AuroraPlasmaBackdrop()
            #if os(macOS)
            VStack(spacing: 14) {
                headerStrip
                HStack(alignment: .top, spacing: 16) {
                    controlCard.frame(maxWidth: .infinity)
                    telemetryCard.frame(maxWidth: .infinity)
                }
            }
            .padding(18)
            #else
            ScrollView {
                VStack(spacing: 14) {
                    headerStrip
                    controlCard
                    telemetryCard
                }
                .padding(14)
            }
            #endif
        }
        .preferredColorScheme(.dark)
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: pickFolderMode ? [.folder] : [.item, .folder],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                let accessed = url.startAccessingSecurityScopedResource()
                if pickFolderMode {
                    vm.outDir = url.path
                } else {
                    vm.filePath = url.path
                }
                if accessed {
                    // Keep copied locally on iOS sandbox if needed, or release after transfer
                }
            }
        }
    }

    private var headerStrip: some View {
        FrostedGlassCard(elevated: true, activeRim: true, radius: 18) {
            VStack(spacing: 10) {
                HStack {
                    HStack(spacing: 8) {
                        Image(systemName: "hexagon.fill")
                            .font(.title2)
                            .foregroundStyle(FrostPalette.primaryGradient)
                        Text("OPENFIR")
                            .font(.system(size: 19, weight: .bold, design: .rounded))
                            .foregroundColor(FrostPalette.textPri)
                        Text("v2.0 FROST")
                            .font(.system(size: 11, weight: .bold, design: .monospaced))
                            .foregroundColor(FrostPalette.cyan)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(FrostPalette.glassInput)
                            .clipShape(Capsule())
                    }
                    Spacer()
                    statusBadge
                }

                HStack(spacing: 8) {
                    ForEach(OpenFIRTab.allCases) { tab in
                        Button {
                            vm.selectedTab = tab
                        } label: {
                            Text(tab.title)
                                .font(.system(size: 12, weight: .bold))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 8)
                                .foregroundColor(vm.selectedTab == tab ? FrostPalette.bgVoid : FrostPalette.textSec)
                                .background(
                                    vm.selectedTab == tab
                                    ? AnyView(FrostPalette.primaryGradient)
                                    : AnyView(FrostPalette.glassInput)
                                )
                                .clipShape(Capsule())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }

    private var statusBadge: some View {
        let (label, col): (String, Color) = {
            switch vm.phase {
            case "done": return ("✓ MERKLE VERIFIED", FrostPalette.mint)
            case "listening": return ("◉ SERVER LIVE", FrostPalette.mint)
            case "transferring", "handshake": return ("◈ STREAM ACTIVE", FrostPalette.cyan)
            case "error": return ("✕ ERROR", FrostPalette.rose)
            default: return ("● IDLE", FrostPalette.textSec)
            }
        }()
        return Text(label)
            .font(.system(size: 11, weight: .bold, design: .monospaced))
            .foregroundColor(col)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(FrostPalette.glassInput)
            .clipShape(Capsule())
    }

    private var controlCard: some View {
        FrostedGlassCard(elevated: false, activeRim: true, radius: 20) {
            VStack(alignment: .leading, spacing: 12) {
                Text(cardTitle)
                    .font(.system(size: 13, weight: .bold, design: .monospaced))
                    .foregroundColor(FrostPalette.cyan)

                if vm.selectedTab == .push || vm.selectedTab == .pull {
                    frostField("SERVER ENDPOINT (host:port)", text: $vm.serverAddr, placeholder: "127.0.0.1:9900")
                    HStack(alignment: .bottom, spacing: 8) {
                        frostField("256-BIT SHARED SECRET", text: $vm.secret, placeholder: "64-hex or pass:...")
                        actionChip("KEYGEN", color: FrostPalette.violet) { vm.generateKey() }
                    }
                    HStack(alignment: .bottom, spacing: 8) {
                        frostField(vm.selectedTab == .push ? "LOCAL FILE / DIRECTORY" : "REMOTE FILE / DIR NAME",
                                   text: $vm.filePath, placeholder: "Select or enter path")
                        if vm.selectedTab == .push {
                            actionChip("BROWSE", color: FrostPalette.cyan) {
                                pickPath(folderOnly: false)
                            }
                        }
                    }
                    if vm.selectedTab == .pull {
                        HStack(alignment: .bottom, spacing: 8) {
                            frostField("LOCAL OUTPUT DIRECTORY", text: $vm.outDir, placeholder: "Output folder")
                            actionChip("BROWSE", color: FrostPalette.cyan) {
                                pickPath(folderOnly: true)
                            }
                        }
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Text("TRANSPORT DATA PLANE")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(FrostPalette.textSec)
                        HStack(spacing: 8) {
                            ForEach([("auto", "AUTO HYBRID"), ("udp", "UDP GSO"), ("tcp", "TLS 1.3 TCP")], id: \.0) { item in
                                Button {
                                    vm.transportMode = item.0
                                } label: {
                                    Text(item.1)
                                        .font(.system(size: 11, weight: .bold))
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 8)
                                        .foregroundColor(vm.transportMode == item.0 ? FrostPalette.bgVoid : FrostPalette.textSec)
                                        .background(vm.transportMode == item.0 ? AnyView(FrostPalette.primaryGradient) : AnyView(FrostPalette.glassInput))
                                        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    Toggle(isOn: $vm.overwrite) {
                        Text("Allow Overwrite  ·  4 TLS Lanes  ·  1000 MiB/s")
                            .font(.system(size: 12))
                            .foregroundColor(FrostPalette.textSec)
                    }
                    .tint(FrostPalette.cyan)
                } else if vm.selectedTab == .server {
                    frostField("LISTEN ADDRESS (:9900 or :443)", text: $vm.listenAddr, placeholder: ":9900")
                    HStack(alignment: .bottom, spacing: 8) {
                        frostField("STORAGE ROOT DIRECTORY", text: $vm.outDir, placeholder: "Storage path")
                        actionChip("BROWSE", color: FrostPalette.cyan) { pickPath(folderOnly: true) }
                    }
                    HStack(alignment: .bottom, spacing: 8) {
                        frostField("SERVER 256-BIT SECRET", text: $vm.secret, placeholder: "64-hex key")
                        actionChip("KEYGEN", color: FrostPalette.violet) { vm.generateKey() }
                    }
                    Text(vm.serverStatus)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(vm.serverHandle != 0 ? FrostPalette.mint : FrostPalette.textSec)
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Zero-Dependency In-Process Protocol Audit:")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(FrostPalette.textPri)
                        suiteRow(1, "4 MiB Hybrid Auto Push + Pull (DEFLATE/Zero/Raw)")
                        suiteRow(2, "17B Shift-Resistant Rabin CDC Cross-Session CAS")
                        suiteRow(3, "10% Burst-Loss Pure UDP + GF(256) RS FEC")
                        suiteRow(4, "ISP UDP Blackhole -> TLS 1.3 TCP Auto-Failover")
                        Text("100% Apache-2.0 clean-room Swift · Zero third-party packages")
                            .font(.system(size: 11))
                            .foregroundColor(FrostPalette.textSec)
                            .padding(.top, 4)
                    }
                }

                Spacer(minLength: 6)

                Button {
                    vm.triggerPrimaryAction()
                } label: {
                    let isStop = (vm.selectedTab == .server && vm.serverHandle != 0) || (vm.selectedTab != .server && vm.activeJob != 0)
                    Text(ctaTitle)
                        .font(.system(size: 14, weight: .bold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                        .foregroundColor(FrostPalette.bgVoid)
                        .background(
                            LinearGradient(
                                colors: isStop
                                    ? [FrostPalette.rose, FrostPalette.magenta]
                                    : (vm.selectedTab == .server ? [FrostPalette.mint, FrostPalette.cyan] : [FrostPalette.cyan, FrostPalette.accentEnd]),
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var telemetryCard: some View {
        FrostedGlassCard(elevated: false, activeRim: false, radius: 20) {
            VStack(alignment: .leading, spacing: 12) {
                Text("LIVE TELEMETRY · ZERO-COPY ENGINE")
                    .font(.system(size: 13, weight: .bold, design: .monospaced))
                    .foregroundColor(FrostPalette.violet)

                HStack {
                    Text(String(format: "%.1f%%", vm.percent))
                        .font(.system(size: 15, weight: .bold, design: .monospaced))
                        .foregroundColor(FrostPalette.textPri)
                    Text("· \(OpenFIRBridge.formatBytes(vm.bytesDone)) / \(OpenFIRBridge.formatBytes(vm.totalBytes))")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(FrostPalette.textSec)
                    Spacer()
                    Text(vm.activeLane)
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundColor(FrostPalette.cyan)
                }

                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule().fill(FrostPalette.glassInput)
                        Capsule()
                            .fill(FrostPalette.primaryGradient)
                            .frame(width: max(6, geo.size.width * CGFloat(min(max(vm.percent, 0), 100) / 100.0)))
                    }
                }
                .frame(height: 12)

                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                    kpiTile("EFFECTIVE GOODPUT", String(format: "%.2f MiB/s", vm.goodputMBps), FrostPalette.cyan)
                    kpiTile("HYBRID WIRE I/O", "U:\(OpenFIRBridge.formatBytes(Int64(vm.wireUDP))) T:\(OpenFIRBridge.formatBytes(Int64(vm.wireTCP)))", FrostPalette.textMono)
                    kpiTile("RABIN CDC CAS / DEDUP", "CAS \(vm.casBlocks) · Z \(vm.zeroBlocks) · D \(vm.compBlocks)", FrostPalette.mint)
                    kpiTile("GF(256) RS FEC & RTT", String(format: "Rec %u · FO %u · %.1fms", vm.fecRecovered, vm.failoverBlocks, vm.rttMs),
                            (vm.fecRecovered > 0 || vm.failoverBlocks > 0) ? FrostPalette.amber : FrostPalette.textPri)
                }

                FrostedGlassCard(elevated: true, activeRim: false, radius: 14) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("REAL-TIME THROUGHPUT SPARKLINE (MiB/s)")
                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                            .foregroundColor(FrostPalette.textSec)
                        NeonSparklineChart(samples: vm.sparkline)
                            .frame(height: 92)
                    }
                }

                HStack {
                    if !vm.merkleHex.isEmpty {
                        Text("✓ MERKLE SHA-256: \(vm.merkleHex)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(FrostPalette.mint)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    } else {
                        Text(vm.message)
                            .font(.system(size: 12))
                            .foregroundColor(vm.phase == "error" ? FrostPalette.rose : FrostPalette.textSec)
                            .lineLimit(2)
                    }
                    Spacer()
                }
                .padding(10)
                .background(FrostPalette.glassInput)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
        }
    }

    private func frostField(_ label: String, text: Binding<String>, placeholder: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(FrostPalette.textSec)
            TextField(placeholder, text: text)
                .textFieldStyle(.plain)
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(FrostPalette.textMono)
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .background(FrostPalette.glassInput)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.14), lineWidth: 1)
                )
        }
    }

    private func actionChip(_ title: String, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(FrostPalette.textPri)
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .background(color.opacity(0.32))
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(color.opacity(0.65), lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
    }

    private func kpiTile(_ label: String, _ value: String, _ color: Color) -> some View {
        FrostedGlassCard(elevated: true, activeRim: false, radius: 14) {
            VStack(alignment: .leading, spacing: 5) {
                Text(label)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(FrostPalette.textSec)
                Text(value)
                    .font(.system(size: 13, weight: .bold, design: .monospaced))
                    .foregroundColor(color)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func suiteRow(_ idx: Int, _ desc: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: vm.suiteIdx >= idx ? "checkmark.circle.fill" : "circle")
                .foregroundColor(vm.suiteIdx >= idx ? FrostPalette.mint : FrostPalette.textSec)
            Text("Suite \(idx): \(desc)")
                .font(.system(size: 12))
                .foregroundColor(vm.suiteIdx >= idx ? FrostPalette.textPri : FrostPalette.textSec)
        }
    }

    private func pickPath(folderOnly: Bool) {
        #if os(macOS)
        let panel = NSOpenPanel()
        panel.canChooseFiles = !folderOnly
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            if folderOnly { vm.outDir = url.path }
            else { vm.filePath = url.path }
        }
        #else
        pickFolderMode = folderOnly
        showFileImporter = true
        #endif
    }

    private var cardTitle: String {
        switch vm.selectedTab {
        case .push: return "PUSH · HYBRID UPLOAD"
        case .pull: return "PULL · MERKLE DOWNLOAD"
        case .server: return "SERVER · DUAL-STACK TLS 1.3 + UDP"
        case .audit: return "AUDIT · 4-SUITE CRYPTO VERIFICATION"
        }
    }

    private var ctaTitle: String {
        if vm.selectedTab == .server {
            return vm.serverHandle != 0 ? "STOP DUAL-STACK SERVER" : "START DUAL-STACK SERVER"
        }
        if vm.activeJob != 0 { return "CANCEL ACTIVE TRANSFER" }
        switch vm.selectedTab {
        case .push: return "LAUNCH HYBRID PUSH"
        case .pull: return "LAUNCH MERKLE PULL"
        case .audit: return "RUN 4-SUITE PROTOCOL AUDIT"
        case .server: return "START DUAL-STACK SERVER"
        }
    }
}
