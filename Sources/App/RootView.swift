import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            TabView {
                SetupView().tabItem { Label("Setup", systemImage: "dot.radiowaves.left.and.right") }
                AppsView().tabItem { Label("Apps", systemImage: "square.grid.2x2") }
                FlowsView().tabItem { Label("Flows", systemImage: "list.bullet.rectangle") }
                RulesView().tabItem { Label("Rules", systemImage: "slider.horizontal.3") }
                RepeaterView().tabItem { Label("Repeater", systemImage: "arrow.triangle.2.circlepath") }
                SettingsView().tabItem { Label("Settings", systemImage: "gearshape") }
            }
            StatusBarView()
        }
    }
}
