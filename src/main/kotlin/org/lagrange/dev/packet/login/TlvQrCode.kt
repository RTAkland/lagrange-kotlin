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
        it.writeUInt(0u)
        it.writeInt(appInfo.appId)
        it.writeInt(appInfo.subAppId)
        it.writeFully(keystore.guid)
        it.writeString(appInfo.packageName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        it.writeString(appInfo.ptVersion, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        it.writeString(appInfo.packageName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv1b() = defineTlv(0x1bu) {
        it.writeUInt(0u) // micro
        it.writeUInt(0u) // version
        it.writeUInt(3u) // size
        it.writeUInt(4u) // margin
        it.writeUInt(72u) // dpi
        it.writeUInt(2u) // eclevel
        it.writeUInt(2u) // hint
        it.writeUShort(0u) // unknown
    }
    
    fun tlv1d() = defineTlv(0x1du) {
        it.writeUByte(1u)
        it.writeInt(appInfo.mainSigMap) // misc bitmap
        it.writeUInt(0u)
        it.writeUByte(0u)
    }
    
    fun tlv33() = defineTlv(0x33u) {
        it.writeFully(keystore.guid)
    }
    
    fun tlv35() = defineTlv(0x35u) {
        it.writeInt(appInfo.ssoVersion)
    }

    fun tlv66() = defineTlv(0x66u) {
        it.writeInt(appInfo.ssoVersion)
    }
    
    fun tlvD1() = defineTlv(0xd1u) {
        val buf = protobufOf(
            1 to 1 to appInfo.os,
            1 to 2 to keystore.deviceName,
            4 to 6 to 1
        )
        
        it.writeFully(buf.toByteArray())
    }
    
    fun build(): ByteArray {
        val packet = BytePacketBuilder()
        
        packet.writeUShort(tlvCount)
        packet.writeFully(builder.build().readBytes())
        
        return packet.build().readBytes()
    }

    private fun defineTlv(tag: UShort, tlv: ((builder: BytePacketBuilder) -> Unit)) {
        tlvCount++
        
        builder.writeUShort(tag)
        builder.barrier({
            tlv(it)
        }, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
}