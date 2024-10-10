package org.lagrange.dev.packet.login

import io.ktor.utils.io.core.*
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.utils.ext.fromHex
import org.lagrange.dev.utils.ext.toHex
import org.lagrange.dev.utils.helper.CryptoHelper
import org.lagrange.dev.utils.proto.*

internal class ntlogin(
    private val keystore: Keystore,
    private val appInfo: AppInfo
) {
    private fun buildNTLoginHead(): ProtoMap = protobufMapOf {
        it[1] = protobufOf(
            1 to keystore.uin.toString()
        )
        it[2] = protobufOf(
            1 to appInfo.os,
            2 to keystore.deviceName,
            3 to appInfo.ntLoginType,
            4 to keystore.guid.toHex()
        )
        it[3] = protobufOf(
            1 to "10.0.19042.0",
            2 to appInfo.appId,
            3 to appInfo.packageName
        )
        it[5] = protobufOf(
            1 to keystore.unusualCookies
        )
    }
    
    fun buildNTLoginPacket(sig: ByteArray): ByteArray {
        if (keystore.keySig == null) {
            throw IllegalStateException("Key exchange not completed")
        }
        
        val proto = protobufOf(
            1 to buildNTLoginHead(),
            2 to protobufOf(
                1 to sig
                // TODO: Captcha
            )
        )
        
        return protobufOf(
            1 to keystore.keySig,
            2 to CryptoHelper.aesGcmEncrypt(proto.toByteArray(), keystore.exchangeKey!!),
            3 to 1
        ).toByteArray()
    }
    
    fun parseNTLogin(response: ByteArray) {
        if (keystore.exchangeKey == null) {
            throw IllegalStateException("Key exchange not completed")
        }
        
        
    }
    
    fun buildKeyExchange(): ByteArray {
        val gcmCalc2Key = "e2733bf403149913cbf80c7a95168bd4ca6935ee53cd39764beebe2e007e3aee".fromHex()
        val serverPub = "049D1423332735980EDABE7E9EA451B3395B6F35250DB8FC56F25889F628CBAE3E8E73077914071EEEBC108F4E0170057792BB17AA303AF652313D17C1AC815E79".fromHex()
        
        val plain1 = protobufOf(
            1 to keystore.uin.toString(),
            2 to keystore.guid
        ).toByteArray()
        val gcmCalc1 = CryptoHelper.aesGcmEncrypt(plain1, keystore.ecdh256.keyExchange(serverPub, false))
        
        val timestamp = System.currentTimeMillis() / 1000
        val plain2 = BytePacketBuilder().apply { 
            writeFully(keystore.ecdh256.getPublicKey(false))
            writeInt(1)
            writeFully(gcmCalc1)
            writeInt(0)
            writeInt(timestamp.toInt())
        }
        val hash = CryptoHelper.sha256(plain2.build().readBytes())
        val gcmCalc2 = CryptoHelper.aesGcmEncrypt(hash, gcmCalc2Key)
        
        return protobufOf(
            1 to keystore.ecdh256.getPublicKey(false),
            2 to 1,
            3 to gcmCalc1,
            4 to timestamp,
            5 to gcmCalc2
        ).toByteArray()
    }
    
    fun parseKeyExchange(response: ByteArray) {
        val proto = ProtoUtils.decodeFromByteArray(response)
        val shareKey = keystore.ecdh256.keyExchange(proto[3].asByteArray, false)
        val decrypted = CryptoHelper.aesGcmDecrypt(proto[1].asByteArray, shareKey)
        
        val decryptedProto = ProtoUtils.decodeFromByteArray(decrypted)
        keystore.exchangeKey = decryptedProto[1].asByteArray
        keystore.keySig = decryptedProto[2].asByteArray
    }
}