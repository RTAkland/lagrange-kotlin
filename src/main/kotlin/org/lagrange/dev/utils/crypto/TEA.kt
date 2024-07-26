package org.lagrange.dev.utils.crypto

object TEA {
    fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        return TeaImpl().encrypt(data, key)
    }

    fun decrypt(data: ByteArray, key: ByteArray): ByteArray {
        return TeaImpl().decrypt(data, key)
    }
}
