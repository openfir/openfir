// SPDX-License-Identifier: Apache-2.0

import SwiftUI

@main
struct OpenFIRMacApp: App {
    @StateObject private var vm = OpenFIRBridge()

    var body: some Scene {
        WindowGroup("OpenFIR v1.1 — Obsidian Frost") {
            OpenFIRMainView(vm: vm)
                .frame(minWidth: 1020, minHeight: 680)
        }
        .windowStyle(.hiddenTitleBar)
    }
}
