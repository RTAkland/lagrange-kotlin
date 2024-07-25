package org.lagrange.dev.org.lagrange.dev.network

data class SsoResponse(
    val retCode: Int,
    val command: String,
    val response: ByteArray,
    val sequence: Int,
    val extra: String? = null
)
