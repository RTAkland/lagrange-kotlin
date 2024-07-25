package org.lagrange.dev.network

import kotlinx.coroutines.Dispatchers
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import org.lagrange.dev.BotContext
import org.lagrange.dev.utils.ext.*
import org.lagrange.dev.utils.generator.StringGenerator
import org.lagrange.dev.utils.proto.protobufOf


class PacketHandler(
    context: BotContext
) {
    private var sequence = 0
    private val host = "msfwifi.3g.qq.com"
    private val port = 8080
    
    private val appInfo = context.appInfo
    private val keystore = context.keystore

    private val selectorManager = ActorSelectorManager(Dispatchers.IO)
    private val socket = aSocket(selectorManager).tcp()
    private lateinit var input: ByteReadChannel
    private lateinit var output: ByteWriteChannel
    
    suspend fun connect() {
        val s = socket.connect(host, port)
        input = s.openReadChannel()
        output = s.openWriteChannel(autoFlush = true)
    }

    private fun buildService(): ByteArray {
        val packet = BytePacketBuilder()
        
        packet.barrier({
            it.writeInt(12)
            it.writeByte(if (keystore.d2.isEmpty()) 2 else 1)
            it.writeBytes(keystore.d2, Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
            it.writeByte(0) // unknown
            it.writeString(keystore.uin.toString(), Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
            it.writeBytes(ByteArray(0), Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        }, Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        
        return packet.build().readBytes()
    }
    
    private fun buildSso(command: String, payload: ByteArray): ByteArray {
        val packet = BytePacketBuilder()
        
        packet.writeInt(sequence++)
        packet.writeInt(appInfo.subAppId)
        packet.writeInt(2052)  // locale id
        packet.writeFully("020000000000000000000000".fromHex())
        packet.writeBytes(keystore.tgt, Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        packet.writeString(command, Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        packet.writeBytes(ByteArray(0), Prefix.UINT_32 or Prefix.INCLUDE_PREFIX) // unknown
        packet.writeString(keystore.guid.toHex(), Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        packet.writeBytes(ByteArray(0), Prefix.UINT_32 or Prefix.INCLUDE_PREFIX) // unknown
        packet.writeString(appInfo.currentVersion, Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        packet.writeBytes(buildSsoReserved(true), Prefix.UINT_32 or Prefix.INCLUDE_PREFIX) // unknown
        packet.writeBytes(payload, Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        
        return packet.build().readBytes()
    }
    
    private fun buildSsoReserved(isSign: Boolean): ByteArray {
        val proto = protobufOf(
            15 to StringGenerator.generateTrace(),
            16 to keystore.uid
        )
        
        if (isSign) {
            proto[24] = protobufOf(
                1 to ByteArray(0),
                2 to ByteArray(0),
                3 to ByteArray(0)
            )
        }
        
        return proto.toByteArray()
    }
    
    private fun parseSso() {
        
    }
    
    private fun parseService() {
        
    }
}