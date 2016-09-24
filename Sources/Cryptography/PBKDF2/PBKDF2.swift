import Foundation

public enum PBKDF2Error: Error {
    case cannotIterateZeroTimes
    case cannotDeriveFromKey([UInt8])
    case cannotDeriveFromSalt([UInt8])
    case keySizeTooBig(UInt)
}

public final class PBKDF2<Variant: Hash> {
    public init() { }

    /// Used to make the block number
    /// Credit to Marcin Krzyzanowski
    private static func integerBytes(blockNum block: UInt32) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 4)
        bytes[0] = UInt8((block >> 24) & 0xFF)
        bytes[1] = UInt8((block >> 16) & 0xFF)
        bytes[2] = UInt8((block >> 8) & 0xFF)
        bytes[3] = UInt8(block & 0xFF)
        return bytes
    }
    
    public static func derive(fromKey key: [UInt8], usingSalt salt: [UInt8], iterating iterations: Int, keyLength keySize: UInt? = nil) throws -> [UInt8] {
        
        func authenticate(innerPadding: [UInt8], outerPadding: [UInt8], message: [UInt8]) throws -> [UInt8] {
            let innerPaddingHash: [UInt8] = try Variant.hash(innerPadding + message)
            let outerPaddingHash: [UInt8] = try Variant.hash(outerPadding + innerPaddingHash)
            
            return outerPaddingHash
        }
        
        let keySize = keySize ?? UInt(Variant.blockSize)
        
        guard iterations > 0 else {
            throw PBKDF2Error.cannotIterateZeroTimes
        }
        
        guard key.count > 0 else {
            throw PBKDF2Error.cannotDeriveFromKey(key)
        }
        
        guard salt.count > 0 else {
            throw PBKDF2Error.cannotDeriveFromSalt(salt)
        }
        
        guard keySize <= UInt(((pow(2,32) as Double) - 1) * Double(Variant.blockSize)) else {
            throw PBKDF2Error.keySizeTooBig(keySize)
        }
        
        // MARK - Precalculate paddings
        var key = key
        
        // If it's too long, hash it first
        if key.count > Variant.blockSize {
            key = try Variant.hash(key)
        }
        
        // Add padding
        if key.count < Variant.blockSize {
            key = key + [UInt8](repeating: 0, count: Variant.blockSize - key.count)
        }
        
        // XOR the information
        var outerPadding = [UInt8](repeating: 0x5c, count: Variant.blockSize)
        var innerPadding = [UInt8](repeating: 0x36, count: Variant.blockSize)
        
        for i in 0..<key.count {
            outerPadding[i] = key[i] ^ outerPadding[i]
        }
        
        for i in 0..<key.count {
            innerPadding[i] = key[i] ^ innerPadding[i]
        }
        
        // MARK - The hashing process
        let blocks = UInt32(ceil(Double(keySize) / Double(Variant.blockSize)))
        var response = [UInt8]()
        
        for block in 1...blocks {
            let s = salt + integerBytes(blockNum: block)
            
            var ui = try authenticate(innerPadding: innerPadding, outerPadding: outerPadding, message: s)
            var u1 = ui
            
            for _ in 0..<iterations - 1 {
                u1 = try authenticate(innerPadding: innerPadding, outerPadding: outerPadding, message: u1)
                ui = xor(ui, u1)
            }
            
            response.append(contentsOf: ui)
        }
        
        return response
    }
    
    public static func validate(key: [UInt8], usingSalt salt: [UInt8], against: [UInt8], iterating iterations: Int) throws -> Bool {
        let newHash = try derive(fromKey: key, usingSalt: salt, iterating: iterations, keyLength: UInt(against.count))
        
        return newHash == against
    }
}
