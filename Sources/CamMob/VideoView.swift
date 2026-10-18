import AppKit
import AVFoundation
import CoreMedia
import SwiftUI
import DahuaRTSP

/// Turns Annex B access units into CMSampleBuffers and hands them to an
/// AVSampleBufferDisplayLayer, which decodes H.264/HEVC in hardware.
final class VideoRenderer {
    let layer = AVSampleBufferDisplayLayer()
    private var format: CMVideoFormatDescription?
    private var codec: VideoCodec?
    private var paramSets: [Int: Data] = [:]
    private(set) var frames = 0
    private var sawKeyframe = false
    private(set) var size: CGSize = .zero
    var onFirstFrame: (() -> Void)?

    init() {
        layer.videoGravity = .resizeAspect
        layer.backgroundColor = NSColor.black.cgColor
    }

    private func nalType(_ n: Data, _ codec: VideoCodec) -> Int {
        codec == .h264 ? Int(n[n.startIndex] & 0x1f) : Int((n[n.startIndex] >> 1) & 0x3f)
    }

    private static func splitAnnexB(_ d: Data) -> [Data] {
        var out: [Data] = []
        let bytes = [UInt8](d)
        var i = 0
        var start = -1
        while i + 2 < bytes.count {
            if bytes[i] == 0, bytes[i + 1] == 0, bytes[i + 2] == 1 {
                if start >= 0 {
                    var end = i
                    if end > 0, bytes[end - 1] == 0 { end -= 1 }
                    if end > start { out.append(Data(bytes[start..<end])) }
                }
                i += 3
                start = i
                continue
            }
            i += 1
        }
        if start >= 0, start < bytes.count { out.append(Data(bytes[start...])) }
        return out
    }

    func enqueue(_ frame: VideoFrame) {
        if codec != frame.codec { codec = frame.codec; format = nil; paramSets = [:] }
        let nals = Self.splitAnnexB(frame.data)
        var vcl: [Data] = []
        var newParams = false
        for n in nals where !n.isEmpty {
            let t = nalType(n, frame.codec)
            let isParam = frame.codec == .h264 ? (t == 7 || t == 8) : (t == 32 || t == 33 || t == 34)
            if isParam {
                if paramSets[t] != n { paramSets[t] = n; newParams = true }
            } else if frame.codec == .h264 ? (t != 9 && t != 6 && t != 12) : (t != 35 && t != 39 && t != 40) {
                vcl.append(n)
            } else {
                vcl.append(n)
            }
        }
        if newParams || format == nil {
            guard let fmt = makeFormat(frame.codec) else { return }
            format = fmt
            if let dims = Optional(CMVideoFormatDescriptionGetDimensions(fmt)) {
                size = CGSize(width: Int(dims.width), height: Int(dims.height))
            }
        }
        guard let fmt = format, !vcl.isEmpty else { return }
        if !sawKeyframe { if frame.keyframe { sawKeyframe = true } else { return } }
        // AVCC/HVCC: 4-byte big-endian length before each NAL.
        var payload = Data()
        for n in vcl {
            var len = UInt32(n.count).bigEndian
            withUnsafeBytes(of: &len) { payload.append(contentsOf: $0) }
            payload.append(n)
        }
        var block: CMBlockBuffer?
        let count = payload.count
        guard CMBlockBufferCreateWithMemoryBlock(allocator: kCFAllocatorDefault, memoryBlock: nil, blockLength: count, blockAllocator: kCFAllocatorDefault,
                                                 customBlockSource: nil, offsetToData: 0, dataLength: count, flags: 0, blockBufferOut: &block) == noErr,
              let bb = block else { return }
        payload.withUnsafeBytes { raw in
            _ = CMBlockBufferReplaceDataBytes(with: raw.baseAddress!, blockBuffer: bb, offsetIntoDestination: 0, dataLength: count)
        }
        var sample: CMSampleBuffer?
        var timing = CMSampleTimingInfo(duration: CMTime(value: 1, timescale: 25),
                                        presentationTimeStamp: CMTime(value: CMTimeValue(frame.timestamp), timescale: 90000),
                                        decodeTimeStamp: .invalid)
        var sizes = [count]
        guard CMSampleBufferCreateReady(allocator: kCFAllocatorDefault, dataBuffer: bb, formatDescription: fmt, sampleCount: 1,
                                        sampleTimingEntryCount: 1, sampleTimingArray: &timing, sampleSizeEntryCount: 1,
                                        sampleSizeArray: &sizes, sampleBufferOut: &sample) == noErr, let sb = sample else { return }
        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: true) as? [NSMutableDictionary], let a = attachments.first {
            a[kCMSampleAttachmentKey_DisplayImmediately] = true
            if !frame.keyframe { a[kCMSampleAttachmentKey_NotSync] = true }
        }
        let wasFirst = frames == 0
        frames += 1
        DispatchQueue.main.async { [self] in
            if layer.status == .failed { layer.flush() }
            layer.enqueue(sb)
            if wasFirst { onFirstFrame?() }
        }
    }

    private func makeFormat(_ codec: VideoCodec) -> CMVideoFormatDescription? {
        var fmt: CMVideoFormatDescription?
        if codec == .h264 {
            guard let sps = paramSets[7], let pps = paramSets[8] else { return nil }
            let sets = [sps, pps]
            return sets[0].withUnsafeBytes { s in
                sets[1].withUnsafeBytes { p in
                    let ptrs: [UnsafePointer<UInt8>] = [s.baseAddress!.assumingMemoryBound(to: UInt8.self), p.baseAddress!.assumingMemoryBound(to: UInt8.self)]
                    let sizes = [sps.count, pps.count]
                    let rc = CMVideoFormatDescriptionCreateFromH264ParameterSets(allocator: kCFAllocatorDefault, parameterSetCount: 2,
                                                                                parameterSetPointers: ptrs, parameterSetSizes: sizes,
                                                                                nalUnitHeaderLength: 4, formatDescriptionOut: &fmt)
                    return rc == noErr ? fmt : nil
                }
            }
        } else {
            guard let vps = paramSets[32], let sps = paramSets[33], let pps = paramSets[34] else { return nil }
            return vps.withUnsafeBytes { v in
                sps.withUnsafeBytes { s in
                    pps.withUnsafeBytes { p in
                        let ptrs: [UnsafePointer<UInt8>] = [v.baseAddress!.assumingMemoryBound(to: UInt8.self), s.baseAddress!.assumingMemoryBound(to: UInt8.self), p.baseAddress!.assumingMemoryBound(to: UInt8.self)]
                        let sizes = [vps.count, sps.count, pps.count]
                        let rc = CMVideoFormatDescriptionCreateFromHEVCParameterSets(allocator: kCFAllocatorDefault, parameterSetCount: 3,
                                                                                    parameterSetPointers: ptrs, parameterSetSizes: sizes,
                                                                                    nalUnitHeaderLength: 4, extensions: nil, formatDescriptionOut: &fmt)
                        return rc == noErr ? fmt : nil
                    }
                }
            }
        }
    }

    func flush() {
        sawKeyframe = false
        format = nil
        DispatchQueue.main.async { self.layer.flushAndRemoveImage() }
    }
}

/// Hosts the display layer in SwiftUI.
struct VideoLayerView: NSViewRepresentable {
    let renderer: VideoRenderer

    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        v.wantsLayer = true
        v.layer = CALayer()
        v.layer?.backgroundColor = NSColor.black.cgColor
        renderer.layer.frame = v.bounds
        renderer.layer.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
        v.layer?.addSublayer(renderer.layer)
        return v
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        renderer.layer.frame = nsView.bounds
    }
}
