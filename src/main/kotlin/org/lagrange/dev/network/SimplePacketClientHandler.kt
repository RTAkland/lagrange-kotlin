package org.lagrange.dev.network;

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandler.Sharable
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.SimpleChannelInboundHandler

@Sharable
class SimplePacketClientHandler : SimpleChannelInboundHandler<ByteBuf>() {
    override fun channelActive(ctx: ChannelHandlerContext?) {
        // like connection is opened
    }
    override fun channelRead0(ctx: ChannelHandlerContext, buf: ByteBuf) {

    }
}