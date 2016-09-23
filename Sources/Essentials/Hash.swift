import Core

public protocol Hash {
    static var blockSize: Int { get }
    
    static func hash(_ bytes: Bytes) throws -> Bytes
}

public protocol StreamingHash: Hash {
    init(_ stream: ByteStream)
    func hash() throws -> Bytes
}
