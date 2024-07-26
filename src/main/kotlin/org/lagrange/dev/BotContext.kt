package org.lagrange.dev

import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.network.PacketHandler
import org.lagrange.dev.packet.login.wtlogin

class BotContext(
    val keystore: Keystore,
    val appInfo: AppInfo
) {
    
    val packet = PacketHandler(keystore, appInfo)
    
    suspend fun fetchQrCode() {
        if (!packet.connected) {
            packet.connect()
        }
        
        val transEmp = wtlogin(keystore, appInfo).buildTransEmp0x31()
        val response = packet.sendPacket("wtlogin.trans_emp", transEmp)
        val parsed = wtlogin(keystore, appInfo).parseTransEmp0x31(response.response)
    }
}