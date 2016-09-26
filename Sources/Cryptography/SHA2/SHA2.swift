internal protocol SHA2_32bits: class, Hash {
    var hash: [UInt32] { get set }
    var k: [UInt64] { get }
    
    init()
}

extension SHA2_32bits {
    internal func process(_ chunk: ArraySlice<UInt8>) {
        if chunk.count != Self.blockSize {
            fatalError("SHA1 internal error - invalid block provided with size \(chunk.count)")
        }
        
        func rightRotate(_ number: UInt32, amount: UInt32) -> UInt32 {
            return (number >> amount) | (number << (32 - amount))
        }
        
        // break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15, big-endian
        // Extend the sixteen 32-bit words into sixty-four 32-bit words:
        var w = [UInt32](repeating: 0, count: k.count)
        for x in 0..<w.count {
            switch (x) {
            case 0...15:
                let start = chunk.startIndex + (x * MemoryLayout.size(ofValue: w[x]))
                let end = start + MemoryLayout.size(ofValue: w[x])
                let le = toUInt32Array(chunk[start..<end])[0]
                w[x] = le.bigEndian
                break
            default:
                let s0 = rightRotate(w[x-15], amount: 7) ^ rightRotate(w[x-15], amount: 18) ^ (w[x-15] >> 3) //FIXME: n
                let s1 = rightRotate(w[x-2], amount: 17) ^ rightRotate(w[x-2], amount: 19) ^ (w[x-2] >> 10)
                w[x] = w[x-16] &+ s0 &+ w[x-7] &+ s1
                break
            }
        }
        
        var a = UInt32(hash[0])
        var b = UInt32(hash[1])
        var c = UInt32(hash[2])
        var d = UInt32(hash[3])
        var e = UInt32(hash[4])
        var f = UInt32(hash[5])
        var g = UInt32(hash[6])
        var h = UInt32(hash[7])
        
        // Main loop
        for i in 0..<k.count {
            let s0 = rightRotate(a, amount: 2) ^ rightRotate(a, amount: 13) ^ rightRotate(a, amount: 22)
            let maj = (a & b) ^ (a & c) ^ (b & c)
            let t2 = s0 &+ maj
            let s1 = rightRotate(e, amount: 6) ^ rightRotate(e, amount: 11) ^ rightRotate(e, amount: 25)
            let ch = (e & f) ^ ((~e) & g)
            let t1 = h &+ s1 &+ ch &+ UInt32(k[i]) &+ w[i]
            
            h = g
            g = f
            f = e
            e = d &+ t1
            d = c
            c = b
            b = a
            a = t1 &+ t2
        }
        
        hash[0] = (hash[0] &+ a)
        hash[1] = (hash[1] &+ b)
        hash[2] = (hash[2] &+ c)
        hash[3] = (hash[3] &+ d)
        hash[4] = (hash[4] &+ e)
        hash[5] = (hash[5] &+ f)
        hash[6] = (hash[6] &+ g)
        hash[7] = (hash[7] &+ h)
    }
}

public final class SHA256: SHA2_32bits {
    public static var blockSize = 64
    
    internal var hash: [UInt32] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    internal let k: [UInt64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    
    public static func hash(_ inputBytes: [UInt8]) -> [UInt8] {
        var bytes = inputBytes + [0x80]
        var inputBlocks = inputBytes.count / blockSize
        
        if inputBytes.count % blockSize != 8 {
            inputBlocks += 1
            bytes.append(contentsOf: [UInt8](repeating: 0, count: ((inputBlocks * blockSize) - 8) - bytes.count))
        }
        
        bytes.append(contentsOf: bitLength(of: inputBytes.count, reversed: false))
        
        let sha2 = SHA256()
        
        for i in 0..<inputBlocks {
            let start = i * blockSize
            let end = (i+1) * blockSize
            sha2.process(bytes[start..<end])
        }
        
        return sha2.hashedBytes
    }
    
    public var hashedBytes: [UInt8] {
        var bytes = [UInt8]()
        
        hash.forEach {
            let item = $0.bigEndian
            bytes += [UInt8(item & 0xff), UInt8((item >> 8) & 0xff), UInt8((item >> 16) & 0xff), UInt8((item >> 24) & 0xff)]
        }
        
        return bytes
    }
}
