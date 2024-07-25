package org.lagrange.dev.common

import org.lagrange.dev.utils.crypto.ECDH
import org.lagrange.dev.utils.crypto.ecdh.EllipticCurve

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
)
