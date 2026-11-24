// SPDX-License-Identifier: Apache-2.0

import SwiftUI

@main
struct OpenFIRMacApp: App {
    @StateObject private var vm = OpenFIRBridge()

    var body: some Scene {
        WindowGroup("OpenFIR v2.0 — Obsidian Frost") {
            OpenFIRMainView(vm: vm)
                .frame(minWidth: 1020, minHeight: 680)
        }
        .windowStyle(.hiddenTitleBar)
    }
}
