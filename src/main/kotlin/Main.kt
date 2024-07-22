package org.lagrange.dev

import io.netty.channel.epoll.EpollEventLoopGroup
import io.netty.channel.epoll.EpollSocketChannel
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioSocketChannel
import org.lagrange.dev.org.lagrange.dev.network.bootstrap.LagrangeBootstrap
import org.lagrange.dev.utils.ext.toHex
import org.lagrange.dev.utils.proto.protobufOf
import java.net.InetSocketAddress

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
fun main() {
    val useEpoll = System.getProperty("os.name") == "Linux"
    val group = if (useEpoll) EpollEventLoopGroup() else NioEventLoopGroup()
    val channel = if (useEpoll) EpollSocketChannel::class.java else NioSocketChannel::class.java
    runCatching {
        val bootstrap = LagrangeBootstrap(InetSocketAddress.createUnresolved("localhost", 2333), group, channel)
        val future = bootstrap.connect().sync()
        future.channel().closeFuture().sync()
    }
    group.shutdownGracefully().sync();
}