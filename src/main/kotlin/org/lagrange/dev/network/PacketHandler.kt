package org.lagrange.dev.network

import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.util.*
import io.ktor.utils.io.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.org.lagrange.dev.network.SsoResponse
import org.lagrange.dev.utils.crypto.TEA
import org.lagrange.dev.utils.ext.*
import org.lagrange.dev.utils.generator.StringGenerator
import org.lagrange.dev.utils.proto.protobufOf
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.GZIPInputStream


class PacketHandler(
    private val keystore: Keystore,
    private val appInfo: AppInfo
) {
    private var sequence = 0
    private val host = "msfwifi.3g.qq.com"
    private val port = 8080

    private val selectorManager = ActorSelectorManager(Dispatchers.IO)
    private val socket = aSocket(selectorManager).tcp()
    private lateinit var input: ByteReadChannel
    private lateinit var output: ByteWriteChannel
    private val pending: ConcurrentHashMap<Int, CompletableDeferred<SsoResponse>> = ConcurrentHashMap()
    private val headLength = 4

    private val logger = LoggerFactory.getLogger(PacketHandler::class.java)

    suspend fun connect() {
        val s = socket.connect(host, port)
        input = s.openReadChannel()
        output = s.openWriteChannel(autoFlush = true)
        logger.info("Connected to $host:$port")
        
        CoroutineScope(Dispatchers.IO).launch {
            handleReceive()
        }
    }
    
    suspend fun sendPacket(command: String, payload: ByteArray): SsoResponse {
        val seq = sequence++
        val sso = buildSso(command, payload, seq)
        val service = buildService(sso)
        output.writeFully(service)
        
        val response = CompletableDeferred<SsoResponse>()
        pending[seq] = response
        return response.await()
    }

    private fun buildService(sso: ByteArray): ByteArray {
        val packet = BytePacketBuilder()
        
        packet.barrier({
            it.writeInt(12)
            it.writeByte(if (keystore.d2.isEmpty()) 2 else 1)
            it.writeBytes(keystore.d2, Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
            it.writeByte(0) // unknown
            it.writeString(keystore.uin.toString(), Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
            it.writeBytes(TEA.encrypt(sso, keystore.d2Key))
        }, Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        
        return packet.build().readBytes()
    }
    
    private fun buildSso(command: String, payload: ByteArray, sequence: Int): ByteArray {
        val packet = BytePacketBuilder()
        
        packet.writeInt(sequence)
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
    
    private suspend fun handleReceive() {
        while (true) {
            try {
                val buffer = ByteArray(headLength)
                input.readFully(buffer)
                val length = buffer.readUInt32BE(0) // prefix included
                val payload = ByteArray(length.toInt() - headLength)
                input.readFully(payload)
                
                val service = parseService(payload)
                val sso = parseSso(service)
                pending.remove(sso.sequence).also { 
                    it?.complete(sso) ?: logger.warn("No pending request for sequence ${sso.sequence}")
                }
            } catch (e: Exception) {
                logger.error("Error while reading packet", e)
            }
        }
    }
    
    private fun parseSso(service: ByteArray): SsoResponse {
        val reader = ByteReadPacket(service)
        
        val headLen = reader.readUInt()
        val sequence = reader.readUInt()
        val retCode = reader.readInt()
        val extra = reader.readString(Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        val command = reader.readString(Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        val msgCookieLength = reader.readInt() - 4
        val msgCookie = reader.readBytes(msgCookieLength)
        val isCompressed = reader.readInt() == 1
        val reserveFieldLength = reader.readInt()
        val reserveField = reader.readBytes(reserveFieldLength)
        var payload = reader.readBytes(Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        
        if (isCompressed) {
            val gzip = GZIPInputStream(payload.inputStream())
            val output = BytePacketBuilder()
            output.writeFully(gzip.readBytes())
            payload = output.build().readBytes()
        }
        
        return if (retCode == 0) {
            SsoResponse(retCode, command, payload, sequence.toInt())
        } else {
            SsoResponse(retCode, command, payload, sequence.toInt(), extra)
        }
    }
    
    private fun parseService(raw: ByteArray): ByteArray {
        val reader = ByteReadPacket(raw)
        
        val length = reader.readUInt()
        val protocol = reader.readUInt()
        val authFlag = reader.readByte()
        val flag = reader.readByte()
        val uin = reader.readString(Prefix.UINT_32 or Prefix.INCLUDE_PREFIX)
        
        if (protocol != 12u && protocol != 13u) throw Exception("Unrecognized protocol: $protocol")
        
        val encrypted = reader.readBytes(reader.remaining.toInt())
        return  when (authFlag) {
            0.toByte() -> encrypted
            1.toByte() -> TEA.decrypt(encrypted, keystore.d2Key)
            2.toByte() -> TEA.decrypt(encrypted, ByteArray(16))
            else -> throw Exception("Unrecognized auth flag: $authFlag")
        }
    }
}