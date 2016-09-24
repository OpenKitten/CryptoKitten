public protocol ByteStream {
    var closed: Bool { get }
    func next(_ max: Int) throws -> ArraySlice<UInt8>
}

public final class BasicByteStream: ByteStream {
    let bytes: [UInt8]
    var index: Int

    public enum Error: Swift.Error {
        case closed
    }

    public var closed: Bool

    public init(_ bytes: [UInt8]) {
        self.bytes = bytes
        index = 0
        closed = false
    }

    public func next(_ max: Int) throws -> ArraySlice<UInt8> {
        guard !closed else {
            throw Error.closed
        }

        var max = max
        if max + index > bytes.count {
            max = bytes.count - index
        }

        let new = bytes.index(index, offsetBy: max)
        let slice = bytes[index..<new]
        index = new

        if index == bytes.count {
            closed = true
        }
        
        return slice
    }
}
