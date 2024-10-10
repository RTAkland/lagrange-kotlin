package org.lagrange.dev.utils.helper

import kotlin.random.Random

internal object CryptoHelper {
    fun aesGcmEncrypt(data: ByteArray, key: ByteArray): ByteArray {
        val iv = Random.nextBytes(12)
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = javax.crypto.spec.SecretKeySpec(key, "AES")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, javax.crypto.spec.GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(data)
        return iv + encrypted
    }
    
    fun aesGcmDecrypt(data: ByteArray, key: ByteArray): ByteArray {
        val iv = data.sliceArray(0..11)
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val secretKey = javax.crypto.spec.SecretKeySpec(key, "AES")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, javax.crypto.spec.GCMParameterSpec(128, iv))
        return cipher.doFinal(data.sliceArray(12 until data.size))
    }
    
    fun sha256(data: ByteArray): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }
}