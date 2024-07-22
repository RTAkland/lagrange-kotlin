package org.lagrange.dev.utils.proto

import com.google.protobuf.CodedOutputStream

class ProtoList(
    val value: ArrayList<ProtoValue>
): ProtoValue {
    constructor(): this(arrayListOf())

    override fun computeSize(tag: Int): Int {
        var size = 0
        value.forEach {
            size += it.computeSize(tag)
        }
        return size
    }

    override fun add(v: ProtoValue) {
        value.add(v)
    }

    override fun size(): Int {
        return value.size
    }

    override fun writeTo(output: CodedOutputStream, tag: Int) {
        value.forEach {
            it.writeTo(output, tag)
        }
    }

    override fun equals(other: Any?): Boolean {
        return this === other
    }

    override fun hashCode(): Int {
        return System.identityHashCode(this)
    }

    override fun toString(): String {
        return "List($value)"
    }
}