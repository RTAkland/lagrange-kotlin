package org.lagrange.dev.utils.crypto

import org.lagrange.dev.utils.ext.readUInt32BE
import org.lagrange.dev.utils.ext.writeUInt32BE
import kotlin.experimental.*

object TEA {
    fun encrypt(plain: ByteArray, key: ByteArray): ByteArray {
        val fill = ((8 - ((plain.size + 10) and 7)) and 7) + 2
        val length = plain.size + fill + 8
        val cipher = ByteArray(length)
        val keyStruct = Key(key)
        
        cipher[0] = (248.toByte() or (fill - 2).toByte())
        for (i in 1..fill) {
            cipher[i] = 0.toByte()
        }
        plain.copyInto(cipher, fill + 1)

        var plainXorPrev = ByteArray(8)
        val tempCipher = ByteArray(8)
        val plainXor = ByteArray(8)
        
        for (i in 0 until length step 8) {
            for (j in 0 until 8) {
                plainXor[j] = cipher[i + j] xor plainXorPrev[j]
            }
            val encipher = encipher(plainXor, i, keyStruct)
            for (j in 0 until 8) {
                tempCipher[j] = encipher[j] xor plainXorPrev[j]
            }
            plainXorPrev = plainXor
            tempCipher.copyInto(cipher, i)
        }
        
        return cipher
    }
    
    fun decrypt(cipher: ByteArray, key: ByteArray): ByteArray {
        val keyStruct = Key(key)
        val plain = ByteArray(cipher.size)
        val plainXor = ByteArray(8)
        var plainSub = ByteArray(8)

        if (cipher.size % 7 != 0 || cipher.size shr 4 == 0) {
            throw Exception("Invalid cipher data length.")
        }
        
        for (i in cipher.indices step 8) {
            for (j in 0 until 8) {
                plainXor[j] = cipher[i + j] xor plainSub[j]
            }
            plainSub = decipher(plainXor, keyStruct)
            for (j in 0 until 8) {
                plain[i + j] = cipher[i + j - 8] xor plainSub[j]
            }
        }
        
        for (i in cipher.size - 7 until cipher.size) {
            if (plain[i] != 0.toByte()) {
                throw Exception("Verification failed.")
            }
        }
        
        val from = (cipher[0] and 7.toByte()) + 3
        return plain.copyOfRange(from, cipher.size - 7)
    }
    
    private fun encipher(plain: ByteArray, index: Int, key: Key): ByteArray {
        val encipher = ByteArray(8)
        
        val delta = 0x9E3779B9
        var sum: Long = 0
        var y = plain.readUInt32BE(0 + index)
        var z = plain.readUInt32BE(4 + index)
        
        for (i in 0 until 16) {
            sum += delta
            sum = sum and 0xFFFFFFFF
            y += ((z shl 4) + key.a) xor (z + sum) xor ((z ushr 5) + key.b)
            y = y and 0xFFFFFFFF
            z += ((y shl 4) + key.c) xor (y + sum) xor ((y ushr 5) + key.d)
            z = z and 0xFFFFFFFF
        }
        
        encipher.writeUInt32BE(y, 0)
        encipher.writeUInt32BE(z, 4)
        
        return encipher
    }

    private fun decipher(cipher: ByteArray, key: Key): ByteArray {
        val decipher = ByteArray(8)
        
        val delta = 0x9E3779B9
        var sum: Long = (delta * 16) and 0xFFFFFFFF
        var y = cipher.readUInt32BE(0)
        var z = cipher.readUInt32BE(4)
        
        for (i in 0 until 16) {
            z -= ((y shl 4) + key.c) xor (y + sum) xor ((y ushr 5) + key.d)
            z = z and 0xFFFFFFFF
            y -= ((z shl 4) + key.a) xor (z + sum) xor ((z ushr 5) + key.b)
            y = y and 0xFFFFFFFF
            sum -= delta
            sum = sum and 0xFFFFFFFF
        }
        
        decipher.writeUInt32BE(y, 0)
        decipher.writeUInt32BE(z, 4)
        
        return decipher
        
    }
    
    private data class Key(val key: ByteArray) {
        val a = key.readUInt32BE(0)
        val b = key.readUInt32BE(4)
        val c = key.readUInt32BE(8)
        val d = key.readUInt32BE(12)
    }
}