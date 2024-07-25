package org.lagrange.dev

import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import org.lagrange.dev.network.PacketHandler

class BotContext(
    val keystore: Keystore,
    val appInfo: AppInfo
) {
    
    val packet = PacketHandler(keystore, appInfo)
}