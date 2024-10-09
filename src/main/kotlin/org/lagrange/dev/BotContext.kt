package org.lagrange.dev

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.network.PacketHandler
import org.lagrange.dev.packet.login.QrCodeState
import org.lagrange.dev.packet.login.ntlogin
import org.lagrange.dev.packet.login.wtlogin
import org.lagrange.dev.utils.ext.toHex
import org.lagrange.dev.utils.proto.ProtoUtils
import org.lagrange.dev.utils.proto.asUtf8String
import org.lagrange.dev.utils.proto.protobufOf
import org.slf4j.LoggerFactory

class BotContext(
    private val keystore: Keystore,
    private val appInfo: AppInfo
) {
    
    private val packet = PacketHandler(keystore, appInfo)
    
    private val logger = LoggerFactory.getLogger(BotContext::class.java)
    
    suspend fun fetchQrCode(): Pair<String, ByteArray> {
        if (!packet.connected) {
            packet.connect()
        }
        
        val transEmp = wtlogin(keystore, appInfo).buildTransEmp0x31()
        val response = packet.sendPacket("wtlogin.trans_emp", transEmp)
        val parsed = wtlogin(keystore, appInfo).parseTransEmp0x31(response.response)
        
        val proto = ProtoUtils.decodeFromByteArray(parsed.getValue(0xd1u))
        return Pair(proto[2].asUtf8String, parsed.getValue(0x17u))
    }
    
    private suspend fun queryState(): QrCodeState {
        val transEmp = wtlogin(keystore, appInfo).buildTransEmp0x12()
        val response = packet.sendPacket("wtlogin.trans_emp", transEmp)
        return wtlogin(keystore, appInfo).parseTransEmp0x12(response.response)
    }
    
    private suspend fun online(): Boolean {
        val proto = protobufOf(
            1 to keystore.guid.toHex().lowercase(),
            2 to 0, // kickPC
            3 to appInfo.currentVersion,
            4 to 0, // IsFirstRegisterProxyOnline
            5 to 2052, // localeId
            6 to protobufOf(
                1 to keystore.deviceName,
                2 to appInfo.kernel,
                3 to "Windows 10.0.19042",
                4 to "",
                5 to appInfo.vendorOs
            ).toByteArray(),
            7 to 0, // SetMute
            8 to 0, // RegisterVendorType
            9 to 1, // RegType
        )
        
        val sso = packet.sendPacket("trpc.qq_new_tech.status_svc.StatusService.Register", proto.toByteArray())
        val parsed = ProtoUtils.decodeFromByteArray(sso.response)
        
        return parsed[2].asUtf8String.contains("register success")
    }
    
    suspend fun loginByQrCode(): Boolean {
        while (true) {
            val state = queryState()

            logger.info("QrCode state: ${state.value}")

            if (state.value == QrCodeState.Confirmed.value) {
                logger.info("QrCode confirmed, trying to login with NoPicSig")
                break
            }
            withContext(Dispatchers.IO) {
                Thread.sleep(2000)
            }
        }
        
        val login = wtlogin(keystore, appInfo).buildLogin()
        val response = packet.sendPacket("wtlogin.login", login)
        val success = wtlogin(keystore, appInfo).parseLogin(response.response)
        
        if (success) {
            return online()
        } else {
            return false
        }
    }
    
    suspend fun loginByToken() {
        if (keystore.d2.isNotEmpty() && keystore.d2Key.isNotEmpty()) {
            val keyExchange = ntlogin(keystore, appInfo).buildKeyExchange()
        } else {
            
        }
    }
}