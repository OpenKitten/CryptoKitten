public class Chunks: Sequence {
    var remainder = [UInt8]()
    let chunkSize: Int
    private var _count = 0
    
    public var count: Int {
        return _count
    }
    
    public init(chunkSize: Int) {
        self.chunkSize = chunkSize
    }
    
    public func append(_ byte: UInt8) {
        remainder += [byte]
        _count += 1
    }
    
    public func append(bytes: [UInt8]) {
        remainder += bytes
        _count += bytes.count
    }
    
    public func append(bytes: ArraySlice<UInt8>) {
        remainder += bytes
        _count += bytes.count
    }
    
    public func makeIterator() -> AnyIterator<[UInt8]> {
        return AnyIterator {
            guard self.remainder.count >= self.chunkSize else {
                return nil
            }
            
            let chunk = Array(self.remainder[0..<self.chunkSize])
            self.remainder.removeFirst(self.chunkSize)
            
            return chunk
        }
    }
}
