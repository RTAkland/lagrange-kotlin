package org.lagrange.dev

import kotlinx.coroutines.runBlocking
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore

fun main() {
    val bot = BotContext(Keystore.generateEmptyKeystore(), AppInfo.linux)
    runBlocking { 
        bot.packet.connect()
    }
}