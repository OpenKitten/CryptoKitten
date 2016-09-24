import Foundation

public protocol SequenceInitializable: Sequence {
    init(_ sequence: [Iterator.Element])
}

/**
    Provides access to hexStrings

    Move to vapor/core
*/
extension SequenceInitializable where Iterator.Element == UInt8 {
    
    public init(hexString: String) {
        var data = [UInt8]()
        
        var gen = hexString.characters.makeIterator()
        while let c1 = gen.next(), let c2 = gen.next() {
            let s = String([c1, c2])
            
            guard let d = UInt8(s, radix: 16) else {
                break
            }
            
            data.append(d)
        }
        
        self.init(data)
    }
}

extension Sequence where Iterator.Element == UInt8 {
    public var hexString: String {
        #if os(Linux)
            return self.lazy.reduce("") { $0 + (NSString(format:"%02x", $1).description) }
        #else
            let s = self.lazy.reduce("") { $0 + String(format:"%02x", $1) }

            return s
        #endif
    }
}

public func bitLength(of length: Int, reversed: Bool = true) -> [UInt8] {
    let lengthBytes = arrayOfBytes(length * 8, length: 8)
    
    return reversed ? lengthBytes.reversed() : lengthBytes
}
