package org.lagrange.dev.common

import org.lagrange.dev.utils.crypto.ECDH
import org.lagrange.dev.utils.crypto.ecdh.EllipticCurve
import org.lagrange.dev.utils.ext.toHex
import kotlin.random.Random

data class Keystore(
    val uin: Long,
    val uid: String,
    
    val tgt: ByteArray,
    val d2: ByteArray,
    val d2Key: ByteArray,
    val tgtgt: ByteArray,
    
    val qrSig: ByteArray,
    
    val guid: ByteArray,
    val deviceName: String,

    val ecdh192: ECDH = ECDH(EllipticCurve.secp192k1),
    val ecdh256: ECDH = ECDH(EllipticCurve.prime256v1)
) {
    companion object {
        fun generateEmptyKeystore(): Keystore {
            return Keystore(
                uin =  0,
                uid =  "",
                tgt =  ByteArray(0),
                d2 =  ByteArray(0),
                d2Key = ByteArray(16),
                tgtgt =  ByteArray(0),
                qrSig = ByteArray(0),
                guid =  ByteArray(16),
                deviceName = "Lagrange-${Random.nextBytes(3).toHex()}")
        }
    }
}