package org.lagrange.dev.packet.login

import io.ktor.utils.io.core.*
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.utils.crypto.TEA
import org.lagrange.dev.utils.ext.Prefix
import org.lagrange.dev.utils.ext.barrier
import org.lagrange.dev.utils.ext.fromHex
import org.lagrange.dev.utils.ext.writeBytes
import kotlin.random.Random

class wtlogin(
    val keystore: Keystore, 
    val appInfo: AppInfo
) {
    
    private val ecdhKey = "04928D8850673088B343264E0C6BACB8496D697799F37211DEB25BB73906CB089FEA9639B4E0260498B51A992D50813DA8".fromHex()
    
    fun buildCode2DPacket(tlvs: ByteArray, command: UShort): ByteArray {
        val newPacket = BytePacketBuilder()
        
        newPacket.writeByte(0x2) // packet Start
        newPacket.writeUShort((43 + tlvs.size + 1).toUShort()) // _head_len = 43 + data.size +1
        newPacket.writeUShort(command)
        newPacket.writeFully(ByteArray(21))
        newPacket.writeByte(0x3)
        newPacket.writeShort(0x0) // close
        newPacket.writeShort(0x32) // Version Code: 50
        newPacket.writeUInt(0u) // trans_emp sequence
        newPacket.writeULong(0.toULong()) // dummy uin
        newPacket.writeFully(tlvs)
        newPacket.writeByte(0x3)
        
        val requestBody = BytePacketBuilder()
        requestBody.writeUInt((System.currentTimeMillis() / 1000).toUInt())
        requestBody.writeFully(newPacket.build().readBytes())
        
        val packet = BytePacketBuilder()
        packet.writeByte(0x0) // encryptMethod == EncryptMethod.EM_ST || encryptMethod == EncryptMethod.EM_ECDH_ST
        packet.writeUShort(requestBody.size.toUShort())
        packet.writeInt(appInfo.appId) // TODO: AppInfo.AppId
        packet.writeInt(0x72) // Role
        packet.writeBytes(ByteArray(0), Prefix.UINT_16 or Prefix.LENGTH_ONLY) // uSt
        packet.writeBytes(ByteArray(0), Prefix.UINT_8 or Prefix.LENGTH_ONLY) // rollback
        packet.writeFully(requestBody.build().readBytes())
        
        return packet.build().readBytes()
    }
    
    fun buildTransEmp0x31() {
        val tlvs = TlvQrCode(keystore, appInfo)
        tlvs.tlv16()
        tlvs.tlv1b()
        tlvs.tlv1d()
        tlvs.tlv33()
        tlvs.tlv35()
        tlvs.tlv66()
        tlvs.tlvD1()
        
        val packet = BytePacketBuilder()
        packet.writeUShort(0u)
        packet.writeUInt(appInfo.appId.toUInt())
        packet.writeULong(0u) // uin
        packet.writeBytes(keystore.qrSig, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        packet.writeByte(0)
        packet.writeBytes(ByteArray(0), Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        packet.writeBytes(tlvs.build())
    }
    
    fun buildTransEmp0x12() {
        val packet = BytePacketBuilder()
        packet.writeUShort(0u)
        packet.writeUInt(appInfo.appId.toUInt())
        packet.writeULong(0u) // uin
        packet.writeBytes(ByteArray(0))
        packet.writeByte(0)
        packet.writeBytes(ByteArray(0), Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        packet.writeUShort(0u) // actually it is the tlv count, but there is no tlv so 0x0 is used
    }
    
    fun buildLogin(payload: ByteArray, command: UShort): ByteArray {
        val encrypted = TEA.encrypt(payload, keystore.ecdh192.keyExchange(ecdhKey, true))
        val packet = BytePacketBuilder()
        
        packet.writeByte(2)
        packet.barrier({
            it.writeUShort(8001u)
            it.writeUShort(command)
            it.writeUShort(0u) // TODO: Sequence
            it.writeUInt(0u) // TODO: Uin
            it.writeByte(3) // extVer
            it.writeByte(135.toByte()) // cmdVer
            it.writeUInt(0u) // actually unknown const 0
            it.writeByte(19) // pubId
            it.writeUShort(0u) // insId
            it.writeUShort(appInfo.appClientVersion.toUShort())
            it.writeUInt(0u) // retryTime
            it.writeBytes(buildEncryptHead(), Prefix.UINT_16 or Prefix.INCLUDE_PREFIX)
            it.writeBytes(encrypted, Prefix.UINT_16 or Prefix.INCLUDE_PREFIX)
            it.writeByte(3)
        }, Prefix.UINT_16 or Prefix.INCLUDE_PREFIX, 1) // addition of 1 aims to include packet start
        
        return packet.build().readBytes()
    }
    
    private fun buildEncryptHead(): ByteArray {
        val packet = BytePacketBuilder()
        
        packet.writeByte(1)
        packet.writeByte(1)
        packet.writeBytes(Random.nextBytes(16))
        packet.writeUShort(0x102u) // unknown const
        packet.writeBytes(keystore.ecdh192.getPublicKey(true), Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        
        return packet.build().readBytes()
    }
}