// SPDX-License-Identifier: Apache-2.0

import SwiftUI

@main
struct OpenFIRiOSApp: App {
    @StateObject private var vm = OpenFIRBridge()

    var body: some Scene {
        WindowGroup {
            OpenFIRMainView(vm: vm)
        }
    }
}
