package org.lagrange.dev.utils.ext

import io.ktor.utils.io.core.*

fun BytePacketBuilder.writeString(value: String, prefix: Prefix = Prefix.NONE) {
    this.writeLength(value.length.toUInt(), prefix)
    this.writeText(value)
}

fun BytePacketBuilder.writeBytes(value: ByteArray, prefix: Prefix = (Prefix.NONE)) {
    this.writeLength(value.size.toUInt(), prefix)
    this.writeFully(value)
}

fun BytePacketBuilder.barrier(target: ((BytePacketBuilder) -> Unit), prefix: Prefix, addition: Int = 0) {
    val written = BytePacketBuilder()
    target(written)
    
    writeLength(written.size.toUInt() + addition.toUInt(), prefix)
    writePacket(written.build())
}

fun ByteReadPacket.readString(prefix: Prefix): String {
    val length = readLength(prefix)
    return this.readText(length.toInt())
}

fun ByteReadPacket.readBytes(prefix: Prefix): ByteArray {
    val length = readLength(prefix)
    return this.readBytes(length.toInt())
}

private fun BytePacketBuilder.writeLength(length: UInt, prefix: Prefix) {
    val prefixLength = prefix.getPrefixLength()
    val includePrefix = prefix.isIncludePrefix()
    val writtenLength = length + (if (includePrefix) prefixLength else 0).toUInt()
    
    when (prefixLength) {
        1 -> this.writeByte(writtenLength.toByte())
        2 -> this.writeUShort(writtenLength.toUShort())
        4 -> this.writeUInt(writtenLength)
    }
}

private fun ByteReadPacket.readLength(prefix: Prefix): UInt {
    val prefixLength = prefix.getPrefixLength()
    val includePrefix = prefix.isIncludePrefix()
    
    return when (prefixLength) {
        1 -> this.readByte().toUInt() - (if (includePrefix) prefixLength else 0).toUInt()
        2 -> this.readUShort().toUInt() - (if (includePrefix) prefixLength else 0).toUInt()
        4 -> this.readUInt() - (if (includePrefix) prefixLength else 0).toUInt()
        else -> 0u
    }
}