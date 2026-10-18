import Foundation
import Compression

enum Gzip {
    /// Inflates a gzip member (RFC 1952). Returns nil if the data is not gzip.
    static func decompress(_ data: Data) -> Data? {
        let b = [UInt8](data)
        guard b.count > 18, b[0] == 0x1f, b[1] == 0x8b, b[2] == 8 else { return nil }
        let flg = b[3]
        var i = 10
        if flg & 0x04 != 0 { guard i + 2 <= b.count else { return nil }; let xlen = Int(b[i]) | Int(b[i + 1]) << 8; i += 2 + xlen }
        if flg & 0x08 != 0 { while i < b.count, b[i] != 0 { i += 1 }; i += 1 }
        if flg & 0x10 != 0 { while i < b.count, b[i] != 0 { i += 1 }; i += 1 }
        if flg & 0x02 != 0 { i += 2 }
        guard i < b.count - 8 else { return nil }
        let isize = Int(b[b.count - 4]) | Int(b[b.count - 3]) << 8 | Int(b[b.count - 2]) << 16 | Int(b[b.count - 1]) << 24
        let capacity = max(isize, 64) + 64
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        defer { dst.deallocate() }
        let n = b[i..<(b.count - 8)].withUnsafeBufferPointer { src in
            compression_decode_buffer(dst, capacity, src.baseAddress!, src.count, nil, COMPRESSION_ZLIB)
        }
        guard n > 0 else { return nil }
        return Data(bytes: dst, count: n)
    }
}
