import Core
import Essentials

/**
    Used to authenticate messages using the `Hash` algorithm
*/
public class HMAC<Variant: StreamingHash> {
    /**
        Create an HMAC authenticator.
    */
    public init() {}

    /**
        Authenticates a message using the provided `Hash` algorithm

        - parameter message: The message to authenticate
        - parameter key: The key to authenticate with

        - returns: The authenticated message
    */
    public func authenticate(_ message: Bytes, key: Bytes) throws -> Bytes {
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
        
        // Hash the information
        let innerPaddingHash: Bytes = try Variant.hash(innerPadding + message)
        let outerPaddingHash: Bytes = try Variant.hash(outerPadding + innerPaddingHash)
        
        return outerPaddingHash
    }
}
