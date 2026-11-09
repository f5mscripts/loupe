import SwiftUI

@main
struct LoupeApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            Group {
                if model.consentAccepted {
                    RootView()
                } else {
                    ConsentView()
                }
            }
            .environment(model)
            .preferredColorScheme(.dark) // dark-first
            .tint(.green)
        }
    }
}
