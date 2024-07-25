package org.lagrange.dev.utils.crypto

import org.lagrange.dev.utils.crypto.ecdh.EllipticCurve
import org.lagrange.dev.utils.crypto.ecdh.EllipticPoint
import org.lagrange.dev.utils.ext.isEven
import java.lang.System.arraycopy
import java.math.BigInteger
import java.security.MessageDigest

class ECDH(
    private val curve: EllipticCurve
) {
    private val secret = createSecret()
    private val public = createPublic(secret)
    
    fun getPublicKey(compress: Boolean): ByteArray {
        return packPublic(public, compress)
    }
    
    fun keyExchange(publicKey: ByteArray, isHash: Boolean = true): ByteArray {
        val ecPub = unpackPublic(publicKey)
        val ecShared = createShared(secret, ecPub)
        return packShared(ecShared, isHash)
    }
    
    private fun unpackPublic(publicKey: ByteArray): EllipticPoint {
        val length = publicKey.size
        if (length != curve.size * 2 + 1 && length != curve.size + 1) throw Exception("Length does not match.")
        
        var x = ByteArray(curve.size)
        arraycopy(publicKey, 1, x, 0, curve.size)
        x.reverse()
        x = x.copyOf(curve.size + 1)
        
        if (publicKey[0] == 0x04.toByte()) {
            var y = ByteArray(curve.size)
            arraycopy(publicKey, curve.size + 1, y, 0, curve.size)
            y.reverse()
            y = y.copyOf(curve.size + 1)
            
            return EllipticPoint(BigInteger(x), BigInteger(y))
        }
        
        val px = BigInteger(x)
        val x3 = px * px * px
        val ax = px * curve.a
        val right = (x3 + ax + curve.b) % curve.p
        
        val tmp = (curve.p + 1.toBigInteger()) shr 2
        var py = right.modPow(tmp, curve.p)
        
        if (!(py.isEven() xor (publicKey[0] == 0x02.toByte()) || !py.isEven() xor (publicKey[0] == 0x03.toByte()))) {
            py = curve.p - py
        }
        
        return EllipticPoint(px, py)
    }
    
    private fun packPublic(ecPub: EllipticPoint, compress: Boolean = true): ByteArray {
        if (compress) {
            var result = ecPub.x.toByteArray()
            if (result.size == curve.size) result = result.copyOf(curve.size + 1)
            
            result = takeReverse(result, curve.size)
            result[0] = if (ecPub.y.isEven() xor (ecPub.y.signum() < 0)) 0x02 else 0x03
            return result
        }
        
        val x = takeReverse(ecPub.x.toByteArray(), curve.size)
        val y = takeReverse(ecPub.y.toByteArray(), curve.size)
        val buffer = ByteArray(curve.size * 2 + 1)
        
        buffer[0] = 0x04
        arraycopy(x, 0, buffer, 1, x.size)
        arraycopy(y, 0, buffer, y.size + 1, x.size)
        
        return buffer
    }
    
    
    private fun packShared(ecShared: EllipticPoint, isHash: Boolean): ByteArray {
        val x = takeReverse(ecShared.x.toByteArray(), curve.size)
        if (!isHash) return x
        
        val md5 = MessageDigest.getInstance("MD5")
        return md5.digest(x.copyOf(curve.size))
    }
    
    private fun createPublic(ecSec: BigInteger): EllipticPoint {
        return createShared(ecSec, curve.g)
    }
    
    private fun createSecret(): BigInteger {
        var result: BigInteger
        val array = ByteArray(curve.size + 1)
        
        do {
            for (i in 0 until curve.size) {
                array[i] = (0..255).random().toByte()
            }
            array[curve.size] = 0
            result = BigInteger(array)
        } while (result < 1.toBigInteger() || result >= curve.n)
        
        return result
    }
    
    private fun createShared(ecSec: BigInteger, ecPub: EllipticPoint): EllipticPoint {
        if (ecSec % curve.n == 0.toBigInteger() || ecPub.isDefault()) {
            return EllipticPoint(0.toBigInteger(), 0.toBigInteger())
        }
        if (ecSec < 0.toBigInteger()) {
            return createShared(-ecSec, -ecPub)
        }

        if (!curve.checkOn(ecPub)) {
            throw Exception("Public key does not correct.")
        }

        var pr = EllipticPoint(0.toBigInteger(), 0.toBigInteger())
        var pa = ecPub
        var sec = ecSec
        while (sec > 0.toBigInteger()) {
            if (sec and 1.toBigInteger() > 0.toBigInteger()) {
                pr = pointAdd(pr, pa)
            }

            pa = pointAdd(pa, pa)
            sec = sec shr 1
        }

        if (!curve.checkOn(pr)) throw Exception("Unknown error.")

        return pr
    }
    
    private fun pointAdd(p1: EllipticPoint, p2: EllipticPoint): EllipticPoint {
        if (p1.isDefault()) return p2
        if (p2.isDefault()) return p1
        if (!curve.checkOn(p1) || !curve.checkOn(p2)) throw Exception()

        val x1 = p1.x
        val x2 = p2.x
        val y1 = p1.y
        val y2 = p2.y
        val m = if (x1 == x2) {
            if (y1 == y2) (3.toBigInteger() * x1 * x1 + curve.a) * modInverse(y1 shl 1, curve.p)
            else return EllipticPoint(0.toBigInteger(), 0.toBigInteger())
        } else {
            (y1 - y2) * modInverse(x1 - x2, curve.p)
        }

        val xr = mod(m * m - x1 - x2, curve.p)
        val yr = mod(m * (x1 - xr) - y1, curve.p)
        val pr = EllipticPoint(xr, yr)
        
        if (!curve.checkOn(pr)) throw Exception()
        return pr
    }
    
    private fun takeReverse(array: ByteArray, length: Int): ByteArray {
        val result = ByteArray(length)
        for (i in 0 until length) {
            result[i] = array[length - 1 - i]
        }
        return result
    }
    
    private fun modInverse(a: BigInteger, p: BigInteger): BigInteger {
        if (a < 0.toBigInteger()) return p - modInverse(-a, p)

        val g = a.gcd(p)
        if (g != 1.toBigInteger()) throw Exception("Inverse does not exist.")

        return a.modPow(p - 2.toBigInteger(), p)
    }
    
    private fun mod(a: BigInteger, b: BigInteger): BigInteger {
        var result = a % b
        if (result < 0.toBigInteger()) result += b
        return result
    }
}