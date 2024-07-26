package org.lagrange.dev

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.network.PacketHandler
import org.lagrange.dev.packet.login.QrCodeState
import org.lagrange.dev.packet.login.wtlogin
import org.lagrange.dev.utils.proto.ProtoUtils
import org.lagrange.dev.utils.proto.asUtf8String
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
        
        CoroutineScope(Dispatchers.IO).launch {
            while (true) {
                val state = queryState()
                
                logger.info("QrCode state: ${state.value}")
                
                if (state.value == QrCodeState.Confirmed.value) {
                    logger.info("QrCode confirmed, trying to login with NoPicSig")
                    break
                }
                Thread.sleep(2000)
            }
        }
        
        val proto = ProtoUtils.decodeFromByteArray(parsed.getValue(0xd1u))
        return Pair(proto[2].asUtf8String, parsed.getValue(0x17u))
    }
    
    suspend fun queryState(): QrCodeState {
        val transEmp = wtlogin(keystore, appInfo).buildTransEmp0x12()
        val response = packet.sendPacket("wtlogin.trans_emp", transEmp)
        return wtlogin(keystore, appInfo).parseTransEmp0x12(response.response)
    }
    
    suspend fun loginByQrCode() {
        
    }
}