package org.lagrange.dev.utils.crypto

internal object TEA {
    fun encrypt(data: ByteArray, key: ByteArray): ByteArray = TeaImpl().encrypt(data, key)

    fun decrypt(data: ByteArray, key: ByteArray): ByteArray = TeaImpl().decrypt(data, key)
}
