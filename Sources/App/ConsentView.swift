import SwiftUI

/// One-time consent gate. Restates the authorized-use-only scope from the README.
struct ConsentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Image(systemName: "magnifyingglass.circle.fill")
                        .font(.system(size: 56))
                        .foregroundStyle(.green)
                        .padding(.top, 40)

                    Text("Loupe")
                        .font(.largeTitle.bold())
                    Text("A per-app traffic instrument for your own devices and apps.")
                        .font(.headline)
                        .foregroundStyle(.secondary)

                    consentRow("You will only use Loupe on your own device, your own apps, or systems you are explicitly authorized to test.")
                    consentRow("You will not use it to intercept traffic from other people's devices or accounts.")
                    consentRow("You understand pcapd capture is read-only and that editing/resending requires instrumenting a target you control (own app, or an app you re-signed with the gadget).")
                    consentRow("You are responsible for complying with the terms of service and laws that apply to anything you test.")

                    Text("Loupe is deliberately built so it can only target what *you* pair, sign, and instrument. There is no remote attach and no mass-targeting.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.top, 8)
                }
                .padding(24)
            }

            Button {
                model.consentAccepted = true
            } label: {
                Text("I understand — authorized use only")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
            .padding(24)
        }
    }

    private func consentRow(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "checkmark.shield.fill").foregroundStyle(.green)
            Text(text).font(.callout)
        }
    }
}
