package org.lagrange.dev

import org.lagrange.dev.utils.ext.toHex
import org.lagrange.dev.utils.proto.protobufOf

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
fun main() {
    val proto = protobufOf(
        1 to 2 to 3 to "666",
        2 to 1,
        3 to arrayOf("1111111")
    )
    println(proto.toByteArray().toHex())
}