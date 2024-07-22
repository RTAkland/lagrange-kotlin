package org.lagrange.dev.org.lagrange.dev.network.bootstrap

import io.netty.bootstrap.Bootstrap
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.socket.SocketChannel
import org.lagrange.dev.org.lagrange.dev.network.SimplePacketClientHandler
import java.net.InetSocketAddress

class LagrangeBootstrap(address: InetSocketAddress,
    group: EventLoopGroup,
    socketChannel: Class<out SocketChannel>) : Bootstrap() {
    init {
        group(group)
        remoteAddress(address)
        channel(socketChannel)
        handler(object : ChannelInitializer<SocketChannel>() {
            override fun initChannel(channel: SocketChannel) {
                channel.pipeline().addLast(SimplePacketClientHandler())
            }
        })
    }
}