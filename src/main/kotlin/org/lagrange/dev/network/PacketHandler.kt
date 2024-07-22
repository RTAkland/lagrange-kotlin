package org.lagrange.dev.network

import org.lagrange.dev.utils.generator.StringGenerator
import org.lagrange.dev.utils.proto.protobufOf


class PacketHandler {
    private fun packService() {
        
    }
    
    private fun packSso() {
        
    }
    
    private fun packSsoReserved(uid: String, isSign: Boolean): ByteArray {
        val proto = protobufOf(
            15 to StringGenerator.generateTrace(),
            16 to uid
        )
        
        if (isSign) {
            proto[24] = protobufOf(
                1 to ByteArray(0),
                2 to ByteArray(0),
                3 to ByteArray(0)
            )
        }
        
        return proto.toByteArray()
    }
}