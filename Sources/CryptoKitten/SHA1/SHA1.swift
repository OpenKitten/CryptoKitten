public final class SHA1: StreamingHash {
    private var hashCode: [UInt32] = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0
    ]
    
    private var stream: ByteStream? = nil
    
    /// Creates a new SHA1 state capable of hasing a Stream of bytes (like a File) efficiently
    public init(_ s: ByteStream) {
        stream = s
    }
    
    internal init() {}
    
    /// SHA1 hashes in blocks of 64 bytes
    public static let blockSize = 64
    public static var digestSize = 20
    
    /// Hashes a message with SHA1
    ///
    /// - parameter inputBytes: The data to hash
    ///
    /// - returns: The hashed bytes with a length of 20 bytes
    public static func hash(_ inputBytes: [UInt8]) -> [UInt8] {
        var bytes = inputBytes + [0x80]
        let remainingBytes = blockSize - (bytes.count % blockSize)
        var inputBlocks = (bytes.count / blockSize) + (remainingBytes == blockSize - 8 ? 0 : 1)
        
        if remainingBytes != 8 {
            if remainingBytes < 8 {
                inputBlocks += 1
            }
            
            bytes.append(contentsOf: [UInt8](repeating: 0, count: ((inputBlocks * blockSize) - 8) - bytes.count))
        }
        
        bytes.append(contentsOf: bitLength(of: inputBytes.count, reversed: false))
        
        let sha1 = SHA1()
        
        for i in 0..<inputBlocks {
            let start = i * blockSize
            let end = (i + 1) * blockSize
            sha1.process(bytes[start..<end])
        }
        
        // return a basic byte stream
        var resultBytes = [UInt8]()
        
        for hashPart in sha1.hashCode {
            // Big Endian is required
            let hashPart = hashPart.bigEndian
            resultBytes += [UInt8(hashPart & 0xff), UInt8((hashPart >> 8) & 0xff), UInt8((hashPart >> 16) & 0xff), UInt8((hashPart >> 24) & 0xff)]
        }
        
        return resultBytes
    }

    /// Hashes all data in the provided stream chunk-by-chunk with SHA1
    ///
    /// - throws: Stream errors
    ///
    /// - returns: The hashed bytes with a length of 20 bytes
    public func hash() throws -> [UInt8] {
        guard let stream = stream else {
            throw HashError.noStreamProvided
        }
        
        var count = 0
        while !stream.closed {
            let slice = try stream.next(SHA1.blockSize)

            if stream.closed {
                var bytes = Array(slice)
                if bytes.count > SHA1.blockSize - 8 {
                    // if the block is slightly too big, just pad and process
                    bytes.append(contentsOf: [UInt8](repeating: 0, count: SHA1.blockSize - bytes.count))

                    process(ArraySlice<UInt8>(bytes))
                    count += bytes.count

                    // give an empty block for padding
                    bytes = []
                } else {
                    // add this block's count to the total
                    count += bytes.count
                }

                // pad and process the last block 
                // adding the bit length
                bytes.append(0x80)
                bytes.append(contentsOf: [UInt8](repeating: 0, count: (SHA1.blockSize - 8) - bytes.count))
                bytes.append(contentsOf: bitLength(of: count, reversed: false))
                process(ArraySlice<UInt8>(bytes))
            } else {
                // if the stream is still open,
                // process as normal
                process(slice)
                count += SHA1.blockSize
            }
        }

        // return a basic byte stream
        var resultBytes = [UInt8]()
        
        for hashPart in hashCode {
            // Big Endian is required
            let hashPart = hashPart.bigEndian
            resultBytes += [UInt8(hashPart & 0xff), UInt8((hashPart >> 8) & 0xff), UInt8((hashPart >> 16) & 0xff), UInt8((hashPart >> 24) & 0xff)]
        }
        
        return resultBytes
    }

    /// Used for processing a single chunk of 64 bytes, not a byte more of less and updates the `hashCode` appropriately
    private func process(_ bytes: ArraySlice<UInt8>) {
        if bytes.count != SHA1.blockSize {
            fatalError("SHA1 internal error - invalid block provided with size \(bytes.count)")
        }

        var w = [UInt32](repeating: 0, count: 80)

        var index = bytes.startIndex

        for j in 0..<w.count {
            switch j {
            // break chunk into sixteen 4-byte big-endian words
            case 0..<16:
                w[j] = UInt32(bytes, fromIndex: index).bigEndian
                index = bytes.index(index, offsetBy: 4)
            // Extend the sixteen 32-bit words into eighty 32-bit words:
            default:
                w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], count: 1)
                break
            }
        }

        var a = hashCode[0]
        var b = hashCode[1]
        var c = hashCode[2]
        var d = hashCode[3]
        var e = hashCode[4]

        // Main loop
        for i in 0...79 {
            var f: UInt32
            var k: UInt32

            switch i {
            case 0...19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
                break
            case 20...39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
                break
            case 40...59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
                break
            case 60...79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
                break
            default:
                fatalError("Impossible switch")
            }

            let temp = (leftRotate(a, count: 5) &+ f &+ e &+ w[i] &+ k) & 0xffffffff
            e = d
            d = c
            c = leftRotate(b, count: 30)
            b = a
            a = temp
        }
        
        let hashA = (hashCode[0] &+ a) & 0xffffffff
        let hashB = (hashCode[1] &+ b) & 0xffffffff
        let hashC = (hashCode[2] &+ c) & 0xffffffff
        let hashD = (hashCode[3] &+ d) & 0xffffffff
        let hashE = (hashCode[4] &+ e) & 0xffffffff
        
        hashCode = [hashA, hashB, hashC, hashD, hashE]
    }
}
