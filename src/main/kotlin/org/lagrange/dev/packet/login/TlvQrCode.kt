package org.lagrange.dev.packet.login

import io.ktor.utils.io.core.*
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.utils.ext.Prefix
import org.lagrange.dev.utils.ext.barrier
import org.lagrange.dev.utils.ext.writeString
import org.lagrange.dev.utils.proto.protobufOf

internal class TlvQrCode(
    private val keystore: Keystore,
    private val appInfo: AppInfo
) {

    private val builder = BytePacketBuilder()
    
    private var tlvCount: UShort = 0u
    
    fun tlv16() = defineTlv(0x16u) {
        writeUInt(0u)
        writeInt(appInfo.appId)
        writeInt(appInfo.subAppId)
        writeFully(keystore.guid)
        writeString(appInfo.packageName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        writeString(appInfo.ptVersion, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        writeString(appInfo.packageName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv1b() = defineTlv(0x1bu) {
        writeUInt(0u) // micro
        writeUInt(0u) // version
        writeUInt(3u) // size
        writeUInt(4u) // margin
        writeUInt(72u) // dpi
        writeUInt(2u) // eclevel
        writeUInt(2u) // hint
        writeUShort(0u) // unknown
    }
    
    fun tlv1d() = defineTlv(0x1du) {
        writeUByte(1u)
        writeInt(appInfo.mainSigMap) // misc bitmap
        writeUInt(0u)
        writeUByte(0u)
    }
    
    fun tlv33() = defineTlv(0x33u) {
        writeFully(keystore.guid)
    }
    
    fun tlv35() = defineTlv(0x35u) {
        writeInt(appInfo.ssoVersion)
    }

    fun tlv66() = defineTlv(0x66u) {
        writeInt(appInfo.ssoVersion)
    }
    
    fun tlvD1() = defineTlv(0xd1u) {
        val buf = protobufOf(
            1 to 1 to appInfo.os,
            1 to 2 to keystore.deviceName,
            4 to 6 to 1
        )
        
        writeFully(buf.toByteArray())
    }
    
    fun build(): ByteArray = BytePacketBuilder().apply {
        writeUShort(tlvCount)
        writeFully(builder.build().readBytes())
    }.build().readBytes()

    private fun defineTlv(tag: UShort, tlv: BytePacketBuilder.() -> Unit) {
        tlvCount++

        builder.writeUShort(tag)
        builder.barrier({
            tlv()
        }, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
}