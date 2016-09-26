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

func toUInt32Array(_ slice: ArraySlice<UInt8>) -> Array<UInt32> {
    var result = Array<UInt32>()
    result.reserveCapacity(16)
    
    for index in stride(from: slice.startIndex, to: slice.endIndex, by: MemoryLayout<UInt32>.size) {
        result.append(toUInt32(slice, from: index))
    }
    return result
}


func toUInt32(_ slice: ArraySlice<UInt8>, from index: Int) -> UInt32 {
    let val1 = UInt32(slice[index.advanced(by: 3)]) << 24
    let val2 = UInt32(slice[index.advanced(by: 2)]) << 16
    let val3 = UInt32(slice[index.advanced(by: 1)]) << 8
    let val4 = UInt32(slice[index])
    return val1 | val2 | val3 | val4
}

func xor(_ lhs: [UInt8], _ rhs: [UInt8]) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: min(lhs.count, rhs.count))
    
    for i in 0..<result.count {
        result[i] = lhs[i] ^ rhs[i]
    }
    
    return result
}

func leftRotate(_ x: UInt32, count c: UInt32) -> UInt32 {
    return (x << c) | (x >> (32 - c))
}
