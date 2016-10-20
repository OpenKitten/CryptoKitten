func arrayOfBytes<T>(_ value:T, length:Int? = nil) -> [UInt8] {
    let totalBytes = length ?? MemoryLayout<T>.size
    
    let valuePointer = UnsafeMutablePointer<T>.allocate(capacity: 1)
    valuePointer.pointee = value

    var bytes = [UInt8](repeating: 0, count: totalBytes)

    valuePointer.withMemoryRebound(to: UInt8.self, capacity: 1) { bytesPointer in
        for j in 0..<min(MemoryLayout<T>.size,totalBytes) {
            bytes[totalBytes - 1 - j] = (bytesPointer + j).pointee
        }

        valuePointer.deinitialize()
        valuePointer.deallocate(capacity: 1)
    }

    return bytes
}

extension Int32 {
    init(_ slice: ArraySlice<UInt8>, fromIndex index: Int? = nil) {
        let index = index ?? slice.startIndex
        
        let val0 = Int32(slice[index.advanced(by: 3)]) << 24
        let val1 = Int32(slice[index.advanced(by: 2)]) << 16
        let val2 = Int32(slice[index.advanced(by: 1)]) << 8
        let val3 = Int32(slice[index])
        
        self = val0 | val1 | val2 | val3
    }
    
    init(_ data: [UInt8]) {
        let val0 = Int32(data[3]) << 24
        let val1 = Int32(data[2]) << 16
        let val2 = Int32(data[1]) << 8
        let val3 = Int32(data[0])
        
        self = val0 | val1 | val2 | val3
    }
}

extension UInt32 {
    init(_ slice: ArraySlice<UInt8>, fromIndex index: Int? = nil) {
        let index = index ?? slice.startIndex
        
        let val0 = UInt32(slice[index.advanced(by: 3)]) << 24
        let val1 = UInt32(slice[index.advanced(by: 2)]) << 16
        let val2 = UInt32(slice[index.advanced(by: 1)]) << 8
        let val3 = UInt32(slice[index])
        
        self = val0 | val1 | val2 | val3
    }
    
    init(_ data: [UInt8]) {
        let val0 = UInt32(data[3]) << 24
        let val1 = UInt32(data[2]) << 16
        let val2 = UInt32(data[1]) << 8
        let val3 = UInt32(data[0])
        
        self = val0 | val1 | val2 | val3
    }
}

func makeUInt32Array(_ slice: ArraySlice<UInt8>) -> [UInt32] {
    var result = [UInt32]()
    
    for index in stride(from: slice.startIndex, to: slice.endIndex, by: 4) {
        result.append(UInt32(slice, fromIndex: index))
    }
    
    return result
}

func makeUInt64Array(_ slice: ArraySlice<UInt8>) -> [UInt64] {
    var result = [UInt64]()
    
    for index in stride(from: slice.startIndex, to: slice.endIndex, by: 8) {
        result.append(UInt64(slice, fromIndex: index))
    }
    
    return result
}

extension UInt64 {
    init(_ slice: ArraySlice<UInt8>, fromIndex index: Int? = nil) {
        let index = index ?? slice.startIndex
        
        let val0 = UInt64(slice[index.advanced(by: 7)]) << 56
        let val1 = UInt64(slice[index.advanced(by: 6)]) << 48
        let val2 = UInt64(slice[index.advanced(by: 5)]) << 40
        let val3 = UInt64(slice[index.advanced(by: 4)]) << 32
        let val4 = UInt64(slice[index.advanced(by: 3)]) << 24
        let val5 = UInt64(slice[index.advanced(by: 2)]) << 16
        let val6 = UInt64(slice[index.advanced(by: 1)]) << 8
        let val7 = UInt64(slice[index])
        
        self = val0 | val1 | val2 | val3 | val4 | val5 | val6 | val7
    }
}

func xor(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: min(lhs.count, rhs.count))
    
    for i in 0..<result.count {
        result[i] = lhs[i] ^ rhs[i]
    }
    
    return result
}

func xor(_ lhs: ArraySlice<UInt8>, _ rhs: ArraySlice<UInt8>) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: min(lhs.count, rhs.count))
    
    for i in 0..<result.count {
        result[i] = lhs[lhs.startIndex.advanced(by: i)] ^ rhs[rhs.startIndex.advanced(by: i)]
    }
    
    return result
}

func leftRotate(_ x: UInt32, count c: UInt32) -> UInt32 {
    return (x << c) | (x >> (32 - c))
}
