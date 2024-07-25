package org.lagrange.dev.common

data class AppInfo(
    val os: String,
    val kernel: String,
    val vendorOs: String,
    val currentVersion: String,
    val miscBitmap: Int,
    val ptVersion: String,
    val ssoVersion: Int,
    val packageName: String,
    val wtLoginSdk: String,
    val appId: Int,
    val subAppId: Int,
    val appClientVersion: Int,
    val mainSigMap: Int,
    val subSigMap: Int,
    val ntLoginType: Int
) {
    companion object {
        val linux = AppInfo(
            os = "Linux",
            kernel = "Linux",
            vendorOs = "linux",
            currentVersion = "3.2.10-25765",
            miscBitmap = 32764,
            ptVersion = "2.0.0",
            ssoVersion = 19,
            packageName = "com.tencent.qq",
            wtLoginSdk = "nt.wtlogin.0.0.1",
            appId = 1600001615,
            subAppId = 537234773,
            appClientVersion = 25765,
            mainSigMap = 169742560,
            subSigMap = 0,
            ntLoginType = 1
        )
    }
}