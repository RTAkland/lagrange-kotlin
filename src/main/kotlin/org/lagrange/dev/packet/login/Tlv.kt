package org.lagrange.dev.packet.login

import kotlin.random.Random
import io.ktor.utils.io.core.*
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.utils.crypto.TEA
import org.lagrange.dev.utils.ext.*

@OptIn(ExperimentalUnsignedTypes::class)
internal class Tlv(
    private val keystore: Keystore,
    private val appInfo: AppInfo
) {
    private val builder = BytePacketBuilder()
    
    private var tlvCount: UShort = 0u
    
    fun tlv18() = defineTlv(0x18u) {
        writeUShort(0u) // ping ver
        writeUInt(5u)
        writeUInt(0u)
        writeUInt(8001u) // app client ver
        writeUInt(keystore.uin.toUInt())
        writeUShort(0u)
        writeUShort(0u)
    }
    
    fun tlv100() = defineTlv(0x100u) {
        writeUShort(0u) // db buf ver
        writeUInt(5u) // sso ver, dont over 7
        writeInt(appInfo.appId)
        writeInt(appInfo.subAppId)
        writeInt(appInfo.appClientVersion) // app client ver
        writeInt(appInfo.mainSigMap)
    }

    fun tlv106A2() = defineTlv(0x106u) {
        writeFully(keystore.a2)
    }
    
    fun tlv106(md5pass: ByteArray) = defineTlv(0x106u) {
        val body = BytePacketBuilder().apply {
            writeUShort(4u) // tgtgt ver
            writeFully(Random.nextBytes(4)) // crypto.randomBytes(4)
            writeUInt(0u) // sso ver
            writeInt(appInfo.appId)
            writeInt(8001) // app client ver
            writeULong(keystore.uin.toULong())
            writeInt((System.currentTimeMillis() / 1000).toInt())
            writeUInt(0u) // dummy ip
            writeByte(1) // save password
            writeFully(md5pass)
            writeFully(keystore.tgt)
            writeUInt(0u)
            writeByte(1) // guid available
            writeFully(keystore.guid)
            writeUInt(1u)
            writeUInt(1u) // login type password
            writeString(keystore.uin.toString(), Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        }

        val buf = BytePacketBuilder()
        
        buf.writeInt(keystore.uin.toInt())
        buf.writeFully(ByteArray(4))
        buf.writeFully(md5pass)
        
        writeBytes(TEA.encrypt(body.build().readBytes(), buf.build().readBytes()))
    }
    
    fun tlv107() = defineTlv(0x107u) {
        writeUShort(1u) // pic type
        writeUByte(0x0du) // captcha type
        writeUShort(0u) // pic size
        writeUByte(1u) // ret type
    }
    
    fun tlv116() = defineTlv(0x116u) {
        writeUByte(0u)
        writeUInt(12058620u)
        writeInt(appInfo.subSigMap)
        writeUByte(0u)
    }
    
    fun tlv124() = defineTlv(0x124u) {
        writeBytes(ByteArray(12))
    }
    
    fun tlv128() = defineTlv(0x128u) {
        writeUShort(0u)
        writeUByte(0u) // guid new
        writeUByte(0u) // guid available
        writeUByte(0u) // guid changed
        writeUInt(0u) // guid flag
        writeString(appInfo.os, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        writeBytes(keystore.guid, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        writeString("", Prefix.UINT_16 or Prefix.LENGTH_ONLY) // brand
    }
    
    fun tlv141() = defineTlv(0x141u) {
        writeString("Unknown", Prefix.UINT_32 or Prefix.LENGTH_ONLY)
        writeUInt(0u)
    }
    
    fun tlv142() = defineTlv(0x142u) {
        writeUShort(0u)
        writeString(appInfo.packageName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv144() = defineTlv(0x144u) {
        val tlvs = Tlv(keystore, appInfo).apply {
            tlv16e()
            tlv147()
            tlv128()
            tlv124()
        }

        writeBytes(TEA.encrypt(tlvs.build(), keystore.tgtgt))
    }
    
    fun tlv145() = defineTlv(0x145u) {
        writeBytes(keystore.guid)
    }
    
    fun tlv147() = defineTlv(0x147u) {
        writeInt(appInfo.appId)
        writeString(appInfo.ptVersion, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        writeString(appInfo.packageName, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv166() = defineTlv(0x166u) {
        writeUByte(5u)
    }
    
    fun tlv16a() = defineTlv(0x16au) {
        writeFully(keystore.noPicSig)
    }
    
    fun tlv16e() = defineTlv(0x16eu) {
        writeString(keystore.deviceName)
    }
    
    fun tlv177() = defineTlv(0x177u) {
        writeUByte(1u)
        writeUInt(0u)
        writeString(appInfo.wtLoginSdk, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
    }
    
    fun tlv191() = defineTlv(0x191u) {
        writeUByte(0u)
    }
    
    fun tlv318() = defineTlv(0x318u) {
        
    }
    
    fun tlv521() = defineTlv(0x521u) {
        writeUInt(0x13u) // product type
        writeString("basicim", Prefix.UINT_16 or Prefix.LENGTH_ONLY)
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