import Core
import Foundation
import Essentials
import HMAC

public enum PBKDF2Error: Error {
    case cannotIterate(times: Int)
    case cannotDeriveFromKey(Bytes)
    case cannotDeriveFromSalt(Bytes)
    case keySizeTooBig(UInt)
}

public final class PBKDF2<Variant: Hash> {
    public init() { }

    /// Used to make the block number
    /// Credit to Marcin Krzyzanowski
    private static func integerBytes(blockNum block: UInt32) -> Bytes {
        var bytes = Bytes(repeating: 0, count: 4)
        bytes[0] = Byte((block >> 24) & 0xFF)
        bytes[1] = Byte((block >> 16) & 0xFF)
        bytes[2] = Byte((block >> 8) & 0xFF)
        bytes[3] = Byte(block & 0xFF)
        return bytes
    }
    
    public static func derive(fromKey key: Bytes, usingSalt salt: Bytes, iterating iterations: Int, keyLength keySize: UInt? = nil) throws -> Bytes {
        
        func authenticate(innerPadding: [UInt8], outerPadding: [UInt8], message: [UInt8]) throws -> [UInt8] {
            let innerPaddingHash: Bytes = try Variant.hash(innerPadding + message)
            let outerPaddingHash: Bytes = try Variant.hash(outerPadding + innerPaddingHash)
            
            return outerPaddingHash
        }
        
        let keySize = keySize ?? UInt(Variant.blockSize)
        
        guard iterations > 0 else {
            throw PBKDF2Error.cannotIterate(times: 0)
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
            key = key + Bytes(repeating: 0, count: Variant.blockSize - key.count)
        }
        
        // XOR the information
        var outerPadding = Bytes(repeating: 0x5c, count: Variant.blockSize)
        var innerPadding = Bytes(repeating: 0x36, count: Variant.blockSize)
        
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
            var s = salt
            s.append(contentsOf: integerBytes(blockNum: block))
            
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
    
    public static func validate(key: Bytes, usingSalt salt: Bytes, against: Bytes, iterating iterations: Int) throws -> Bool {
        let newHash = try derive(fromKey: key, usingSalt: salt, iterating: iterations, keyLength: UInt(against.count))
        
        return newHash == against
    }
}
