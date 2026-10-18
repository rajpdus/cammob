import Foundation
import CoreGraphics
import ImageIO
import Vision

enum QRImage {
    static func decode(path: String) -> [String] {
        let url = URL(fileURLWithPath: path)
        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil), let img = CGImageSourceCreateImageAtIndex(src, 0, nil) else { return [] }
        let req = VNDetectBarcodesRequest()
        req.symbologies = [.qr, .dataMatrix, .aztec]
        try? VNImageRequestHandler(cgImage: img, options: [:]).perform([req])
        return (req.results ?? []).compactMap { $0.payloadStringValue }
    }
}
