package org.lagrange.dev

import kotlinx.coroutines.runBlocking
import org.lagrange.dev.common.AppInfo
import org.lagrange.dev.common.Keystore
import java.nio.file.Files
import java.nio.file.Paths

fun main() {
    val bot = BotContext(Keystore.generateEmptyKeystore(), AppInfo.linux)
    val (url, qrcode) = runBlocking { 
        bot.fetchQrCode()
    }
    // /Users/wenxuanlin/Desktop/Project/OicqRepos/lagrange-kotlin
    Files.write(Paths.get("/Users/wenxuanlin/Desktop/Project/OicqRepos/lagrange-kotlin/qrcode.png"), qrcode)

    runBlocking {
        bot.loginByQrCode()
    }

    Thread.sleep(Long.MAX_VALUE)
}