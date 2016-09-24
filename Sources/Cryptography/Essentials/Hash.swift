public protocol Hash {
    static var blockSize: Int { get }
    
    static func hash(_ bytes: [UInt8]) throws -> [UInt8]
}

public protocol StreamingHash: Hash {
    init(_ stream: ByteStream)
    func hash() throws -> [UInt8]
}
