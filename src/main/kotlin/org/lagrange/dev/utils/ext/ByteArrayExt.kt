package org.lagrange.dev.utils.ext

fun ByteArray.toHex(): String {
    return joinToString("") {
        it.toInt().and(0xff).toString(16).padStart(2, '0')
    }
}

fun ByteArray.writeUInt32BE(value: Long, offset: Int) {
    this[offset] = (value shr 24).toByte()
    this[offset + 1] = (value shr 16).toByte()
    this[offset + 2] = (value shr 8).toByte()
    this[offset + 3] = value.toByte()
}

fun ByteArray.readUInt32BE(offset: Int): Long {
    return (this[offset].toLong() shl 24) or
            ((this[offset + 1].toLong() and 0xff) shl 16) or
            ((this[offset + 2].toLong() and 0xff) shl 8) or
            (this[offset + 3].toLong() and 0xff)
}