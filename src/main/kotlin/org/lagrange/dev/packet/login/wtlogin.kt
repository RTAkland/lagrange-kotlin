package org.lagrange.dev.packet.login

import io.ktor.utils.io.core.*
import io.ktor.utils.io.core.readBytes
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.utils.crypto.TEA
import org.lagrange.dev.utils.ext.*
import kotlin.random.Random

internal class wtlogin(
    val keystore: Keystore, 
    val appInfo: AppInfo
) {
    
    private val ecdhKey = "04928D8850673088B343264E0C6BACB8496D697799F37211DEB25BB73906CB089FEA9639B4E0260498B51A992D50813DA8".fromHex()
    
    fun buildTransEmp0x31(): ByteArray {
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
        packet.writeBytes(ByteArray(0))
        packet.writeByte(0)
        packet.writeBytes(ByteArray(0), Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        packet.writeBytes(tlvs.build())

        return buildCode2DPacket(packet.build().readBytes(), 0x31u)
    }
    
    fun buildTransEmp0x12(): ByteArray {
        val packet = BytePacketBuilder()
        packet.writeUShort(0u)
        packet.writeUInt(appInfo.appId.toUInt())
        packet.writeBytes(keystore.qrSig, Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        packet.writeULong(0u) // uin
        packet.writeByte(0)
        packet.writeBytes(ByteArray(0), Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        packet.writeUShort(0u) // actually it is the tlv count, but there is no tlv so 0x0 is used
        
        return buildCode2DPacket(packet.build().readBytes(), 0x12u)
    }

    fun buildLogin(): ByteArray {
        val packet = BytePacketBuilder()

        return buildWtLogin(packet.build().readBytes(), 2064u)
    }

    fun parseTransEmp0x31(raw: ByteArray): Map<UShort, ByteArray> {
        val wtlogin = parseWtLogin(raw)
        val code2d = parseCode2DPacket(wtlogin)
        
        val reader = ByteReadPacket(code2d)
        reader.discard(1)
        
        val sig = reader.readBytes(Prefix.UINT_16 or Prefix.LENGTH_ONLY)
        val tlv = readTlv(reader)
        keystore.qrSig = sig
        
        return tlv
    }

    fun parseTransEmp0x12(raw: ByteArray): QrCodeState {
        val wtlogin = parseWtLogin(raw)
        val code2d = parseCode2DPacket(wtlogin)
        
        val reader = ByteReadPacket(code2d)
        val retCode = QrCodeState(reader.readByte())
        if (retCode.value == QrCodeState.Confirmed.value) {
            reader.discard(4)
            keystore.uin = reader.readUInt().toLong()
            reader.discard(4)
            
            val tlv = readTlv(reader)
            keystore.tgtgt = tlv[0x1eu]!!
            keystore.a2 = tlv[0x18u]!!
            keystore.noPicSig = tlv[0x19u]!!
        }
        
        return retCode
    }
    
    fun parseLogin(raw: ByteArray) {
        val wtlogin = parseWtLogin(raw)

    }

    private fun buildCode2DPacket(tlvs: ByteArray, command: UShort): ByteArray {
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

        return buildWtLogin(packet.build().readBytes(), 2066u)
    }
    
    private fun parseCode2DPacket(wtlogin: ByteArray): ByteArray {
        val reader = ByteReadPacket(wtlogin)
        
        val packetLength = reader.readUInt()
        reader.discard(4)
        val command = reader.readUShort()
        reader.discard(40)
        val appId = reader.readUInt()
        
        return reader.readBytes(reader.remaining.toInt())
    }
    
    private fun buildWtLogin(payload: ByteArray, command: UShort): ByteArray {
        val encrypted = TEA.encrypt(payload, keystore.ecdh192.keyExchange(ecdhKey, true))
        val packet = BytePacketBuilder()
        
        packet.writeByte(2)
        packet.barrier({
            it.writeUShort(8001u)
            it.writeUShort(command)
            it.writeUShort(0u) // TODO: Sequence
            it.writeUInt(keystore.uin.toUInt()) // TODO: Uin
            it.writeByte(3) // extVer
            it.writeByte(135.toByte()) // cmdVer
            it.writeUInt(0u) // actually unknown const 0
            it.writeByte(19) // pubId
            it.writeUShort(0u) // insId
            it.writeUShort(appInfo.appClientVersion.toUShort())
            it.writeUInt(0u) // retryTime
            it.writeFully(buildEncryptHead())
            it.writeFully(encrypted)
            it.writeByte(3)
        }, Prefix.UINT_16 or Prefix.INCLUDE_PREFIX, 1) // addition of 1 aims to include packet start
        
        return packet.build().readBytes()
    }
    
    private fun parseWtLogin(raw: ByteArray): ByteArray {
        val reader = ByteReadPacket(raw)
        val header = reader.readByte()
        if (header != 0x02.toByte()) throw Exception("Invalid Header")
        
        val internalLength = reader.readUShort()
        val ver = reader.readUShort()
        val cmd = reader.readUShort()
        val sequence = reader.readUShort()
        val uin = reader.readUInt()
        val flag = reader.readByte()
        val retryTime = reader.readUShort()
        
        val encrypted = reader.readBytes(reader.remaining.toInt() - 1)
        val decrypted = TEA.decrypt(encrypted, keystore.ecdh192.keyExchange(ecdhKey, true))
        if (reader.readByte() != 0x03.toByte()) throw Exception("Packet end not found")
        
        return decrypted
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
    
    private fun readTlv(reader: ByteReadPacket): Map<UShort, ByteArray> {
        val tlvCount = reader.readUShort()
        val result = mutableMapOf<UShort, ByteArray>()
        for (i in 0 until tlvCount.toInt()) {
            val tag = reader.readUShort()
            val length = reader.readUShort()
            val value = reader.readBytes(length.toInt())
            
            result[tag] = value
        }
        
        return result
    }
}