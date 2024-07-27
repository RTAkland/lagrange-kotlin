package org.lagrange.dev.packet.login

import kotlin.random.Random
import io.ktor.utils.io.core.*
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.utils.crypto.TEA
import org.lagrange.dev.utils.ext.*

internal class Tlv(
    private val keystore: Keystore,
    private val appInfo: AppInfo
) {
    private val builder = BytePacketBuilder()
    
    private var tlvCount: UShort = 0u
    
    fun tlv18() = defineTlv(0x18u) {
        it.writeUShort(0u) // ping ver
        it.writeUInt(5u)
        it.writeUInt(0u)
        it.writeUInt(8001u) // app client ver
        it.writeUInt(keystore.uin.toUInt())
        it.writeUShort(0u)
        it.writeUShort(0u)
    }
    
    fun tlv100() = defineTlv(0x100u) {
        it.writeUShort(0u) // db buf ver
        it.writeUInt(5u) // sso ver, dont over 7
        it.writeInt(appInfo.appId)
        it.writeInt(appInfo.subAppId)
        it.writeInt(appInfo.appClientVersion) // app client ver
        it.writeInt(appInfo.mainSigMap)
    }
    
    fun tlv106(md5pass: ByteArray) = defineTlv(0x106u) {
        val body = BytePacketBuilder()
        
        body.writeUShort(4u) // tgtgt ver
        body.writeFully(Random.nextBytes(4)) // crypto.randomBytes(4)
        body.writeUInt(0u) // sso ver
        body.writeInt(appInfo.appId)
        body.writeInt(8001) // app client ver
        body.writeULong(keystore.uin.toULong())
        body.writeInt((System.currentTimeMillis() / 1000).toInt())
        body.writeUInt(0u) // dummy ip
        body.writeByte(1) // save password
        body.writeFully(md5pass)
        body.writeFully(keystore.tgt)
        body.writeUInt(0u)
        body.writeByte(1) // guid available
        body.writeFully(keystore.guid)
        body.writeUInt(1u)
        body.writeUInt(1u) // login type password
        body.writeString(keystore.uin.toString(), Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        
        val buf = BytePacketBuilder()
        
        buf.writeInt(keystore.uin.toInt())
        buf.writeFully(ByteArray(4))
        buf.writeFully(md5pass)
        
        it.writeBytes(TEA.encrypt(body.build().readBytes(), buf.build().readBytes()))
    }
    
    fun tlv107() = defineTlv(0x107u) {
        it.writeUShort(1u) // pic type
        it.writeUByte(0u) // captcha type
        it.writeUShort(0x000du) // pic size
        it.writeUByte(1u) // ret type
    }
    
    fun tlv116() = defineTlv(0x116u) {
        it.writeUByte(0u)
        it.writeUInt(12058620u)
        it.writeInt(appInfo.subSigMap)
        it.writeUByte(0u)
    }
    
    fun tlv124() = defineTlv(0x124u) {
        it.writeBytes(ByteArray(12))
    }
    
    fun tlv128() = defineTlv(0x128u) {
        it.writeUShort(0u)
        it.writeUByte(0u) // guid new
        it.writeUByte(1u) // guid available
        it.writeUByte(0u) // guid changed
        it.writeUInt(0u) // guid flag
        it.writeString(appInfo.os, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        it.writeBytes(keystore.guid, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        it.writeString("", Prefix.UINT_16 or Prefix.LENGTH_ONLY) // brand
    }
    
    fun tlv141() = defineTlv(0x141u) {
        it.writeString("Unknown", Prefix.UINT_32 or Prefix.LENGTH_ONLY)
        it.writeUInt(0u)
    }
    
    fun tlv142() = defineTlv(0x142u) {
        it.writeUShort(0u)
        it.writeString(appInfo.packageName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv144() = defineTlv(0x144u) {
        val tlvs = Tlv(keystore, appInfo)
        
        tlvs.tlv16e()
        tlvs.tlv147()
        tlvs.tlv128()
        tlvs.tlv124()
        
        it.writeBytes(TEA.encrypt(tlvs.build(), keystore.tgtgt))
    }
    
    fun tlv145() = defineTlv(0x145u) {
        it.writeString(keystore.guid.toHex())
    }
    
    fun tlv147() = defineTlv(0x147u) {
        it.writeInt(appInfo.appId)
        it.writeString(appInfo.ptVersion, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        it.writeString(appInfo.packageName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv166() = defineTlv(0x166u) {
        it.writeUByte(5u)
    }
    
    fun tlv16e() = defineTlv(0x16eu) {
        it.writeString(keystore.deviceName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv177() = defineTlv(0x177u) {
        it.writeUByte(1u)
        it.writeUInt(0u)
        it.writeString(appInfo.wtLoginSdk, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv191() = defineTlv(0x191u) {
        it.writeUByte(0u)
    }
    
    fun tlv318() = defineTlv(0x318u) {
        
    }
    
    fun tlv521() = defineTlv(0x521u) {
        it.writeUInt(0x13u) // product type
        it.writeString("basicim", Prefix.UINT_16 or Prefix.LENGTH_ONLY)
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