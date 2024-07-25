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