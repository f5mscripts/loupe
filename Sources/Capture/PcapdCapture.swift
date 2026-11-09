import Foundation
#if canImport(LoupeFFI)
import LoupeFFI
#endif

/// Drives a passive pcapd capture and publishes `Flow` metadata into the store.
/// READ-ONLY layer: it sees that traffic happened; HTTPS bodies stay ciphertext.
@MainActor
final class PcapdCapture {

    private weak var store: FlowStore?
    private let builder = FlowBuilder()
    private var captureHandle: OpaquePointer?
    private var ctxToken: UnsafeMutableRawPointer?
    private var evictTask: Task<Void, Never>?

    init(store: FlowStore) { self.store = store }

    var isRunning: Bool { captureHandle != nil }

    func start(provider: OpaquePointer) throws {
        #if canImport(LoupeFFI)
        guard captureHandle == nil else { return }

        // Pass `self` as the opaque context to the C callback via Unmanaged.
        let ctx = Unmanaged.passRetained(self).toOpaque()
        ctxToken = ctx
        var cap: OpaquePointer?

        let code = loupe_capture_start(
            provider,
            pcapTrampoline,     // extern "C" fn pointer
            ctx,
            &cap
        )
        guard Int(code) == Int(LOUPE_OK), let cap else {
            Unmanaged<PcapdCapture>.fromOpaque(ctx).release()
            ctxToken = nil
            throw DeviceError.pcapd
        }
        captureHandle = cap
        store?.isCapturing = true

        evictTask = Task { [builder] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                await builder.evictIdle()
            }
        }
        #else
        throw DeviceError.notWired
        #endif
    }

    func stop() {
        #if canImport(LoupeFFI)
        if let h = captureHandle {
            loupe_capture_stop(h)
            captureHandle = nil
        }
        if let ctx = ctxToken {
            Unmanaged<PcapdCapture>.fromOpaque(ctx).release()
            ctxToken = nil
        }
        #endif
        evictTask?.cancel(); evictTask = nil
        store?.isCapturing = false
        Task { await builder.reset() }
    }

    // Called (off the main thread) from the C trampoline with one pcapd record.
    fileprivate func handleRecord(_ record: [UInt8]) {
        guard let ip = Self.stripToIP(record) else { return }
        guard let parsed = PacketParser.parse(ip) else { return }
        let bytes = record.count
        let focused = store?.focusedBundleId

        Task { [builder, weak store] in
            let flow = await builder.ingest(parsed, bytes: bytes, bundleId: nil)
            await MainActor.run {
                // pcapd has no per-app attribution; tag with focus only as a hint,
                // and only if nothing better. (Frida flows carry the real bundleId.)
                var f = flow
                if f.bundleId == nil { f.bundleId = focused }
                store?.ingestPcap(f)
            }
        }
    }

    /// pcapd records are a device header + a link-layer frame. The exact header and
    /// link type vary; we locate the IP packet by scanning for a plausible IPv4/IPv6
    /// header at common offsets (0 = raw IP, 4 = BSD loopback/null, 14 = Ethernet).
    static func stripToIP(_ record: [UInt8]) -> [UInt8]? {
        for off in [0, 4, 14, 16] where record.count > off + 20 {
            let v = record[off] >> 4
            if v == 4 || v == 6 {
                return Array(record[off...])
            }
        }
        return nil
    }
}

#if canImport(LoupeFFI)
/// C ABI trampoline: recovers the PcapdCapture from `ctx` and forwards the record.
private func pcapTrampoline(ctx: UnsafeMutableRawPointer?, data: UnsafePointer<UInt8>?, len: Int) {
    guard let ctx, let data else { return }
    let obj = Unmanaged<PcapdCapture>.fromOpaque(ctx).takeUnretainedValue()
    let record = Array(UnsafeBufferPointer(start: data, count: len))
    Task { @MainActor in obj.handleRecord(record) }
}
#endif
