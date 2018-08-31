/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslHandler;
import org.apache.zookeeper.ClientCnxn.EndOfStreamException;
import org.apache.zookeeper.ClientCnxn.Packet;
import org.apache.zookeeper.client.ZKClientConfig;
import org.apache.zookeeper.common.ClientX509Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static org.apache.zookeeper.common.X509Exception.SSLContextException;

/**
 * ClientCnxnSocketNetty implements ClientCnxnSocket abstract methods.
 * It's responsible for connecting to server, reading/writing network traffic and
 * being a layer between network data and higher level packets.
 */
public class ClientCnxnSocketNetty extends ClientCnxnSocket {
    private static final Logger LOG = LoggerFactory.getLogger(ClientCnxnSocketNetty.class);

    private final EventLoopGroup eventLoopGroup;
    private Channel channel;
    private CountDownLatch firstConnect;
    private ChannelFuture connectFuture;
    private final Lock connectLock = new ReentrantLock();
    private final AtomicBoolean disconnected = new AtomicBoolean();
    private final AtomicBoolean needSasl = new AtomicBoolean();
    private final Semaphore waitSasl = new Semaphore(0);

    private static final AtomicReference<ByteBufAllocator> TEST_ALLOCATOR =
            new AtomicReference<>(null);

    ClientCnxnSocketNetty(ZKClientConfig clientConfig) throws IOException {
        this.clientConfig = clientConfig;
        eventLoopGroup = new NioEventLoopGroup(0, Executors.newCachedThreadPool());
        initProperties();
    }

    /**
     * lifecycles diagram:
     * <p/>
     * loop:
     * - try:
     * - - !isConnected()
     * - - - connect()
     * - - doTransport()
     * - catch:
     * - - cleanup()
     * close()
     * <p/>
     * Other non-lifecycle methods are in jeopardy getting a null channel
     * when calling in concurrency. We must handle it.
     */

    @Override
    boolean isConnected() {
        // Assuming that isConnected() is only used to initiate connection,
        // not used by some other connection status judgement.
        connectLock.lock();
        try {
            return connectFuture != null || channel != null;
        } finally {
            connectLock.unlock();
        }
    }

    @Override
    void connect(InetSocketAddress addr) throws IOException {
        firstConnect = new CountDownLatch(1);

        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(Objects.requireNonNull(eventLoopGroup))
                .channel(NioSocketChannel.class)
                .handler(new ZKClientPipelineFactory(addr.getHostString(), addr.getPort()))
                .option(ChannelOption.SO_LINGER, -1)
                .option(ChannelOption.TCP_NODELAY, true);
        ByteBufAllocator testAllocator = TEST_ALLOCATOR.get();
        if (testAllocator != null) {
            bootstrap.option(ChannelOption.ALLOCATOR, testAllocator);
        }
        bootstrap.validate();

        connectLock.lock();
        try {
            connectFuture = bootstrap.connect(addr);
            connectFuture.addListener(new ChannelFutureListener() {
                @Override
                public void operationComplete(ChannelFuture channelFuture) throws Exception {
                    // this lock guarantees that channel won't be assigned after cleanup().
                    connectLock.lock();
                    try {
                        if (!channelFuture.isSuccess()) {
                            LOG.info("future isn't success, cause:", channelFuture.cause());
                            return;
                        } else if (connectFuture == null) {
                            LOG.info("connect attempt cancelled");
                            // If the connect attempt was cancelled but succeeded
                            // anyway, make sure to close the channel, otherwise
                            // we may leak a file descriptor.
                            channelFuture.channel().close();
                            return;
                        }
                        // setup channel, variables, connection, etc.
                        channel = channelFuture.channel();

                        disconnected.set(false);
                        initialized = false;
                        lenBuffer.clear();
                        incomingBuffer = lenBuffer;

                        sendThread.primeConnection();
                        updateNow();
                        updateLastSendAndHeard();

                        if (sendThread.tunnelAuthInProgress()) {
                            waitSasl.drainPermits();
                            needSasl.set(true);
                            sendPrimePacket();
                        } else {
                            needSasl.set(false);
                        }
                        LOG.info("channel is connected: {}", channelFuture.channel());
                    } finally {
                        connectFuture = null;
                        connectLock.unlock();
                        // we need to wake up on connect success or failure to
                        // avoid timeout.
                        wakeupCnxn();
                        firstConnect.countDown();
                    }
                }
            });
        } finally {
            connectLock.unlock();
        }
    }

    @Override
    void cleanup() {
        connectLock.lock();
        try {
            if (connectFuture != null) {
                connectFuture.cancel(false);
                connectFuture = null;
            }
            if (channel != null) {
                channel.close();
                channel = null;
            }
        } finally {
            connectLock.unlock();
        }
        Iterator<Packet> iter = outgoingQueue.iterator();
        while (iter.hasNext()) {
            Packet p = iter.next();
            if (p == WakeupPacket.getInstance()) {
                iter.remove();
            }
        }
    }

    @Override
    void close() {
        if (!eventLoopGroup.isShuttingDown()) {
            eventLoopGroup.shutdownGracefully();
        }
    }

    @Override
    void saslCompleted() {
        needSasl.set(false);
        waitSasl.release();
    }

    @Override
    void connectionPrimed() {
    }

    @Override
    void packetAdded() {
    }

    @Override
    void onClosing() {
        firstConnect.countDown();
        wakeupCnxn();
        LOG.info("channel is told closing");
    }

    private void wakeupCnxn() {
        if (needSasl.get()) {
            waitSasl.release();
        }
        outgoingQueue.add(WakeupPacket.getInstance());
    }

    @Override
    void doTransport(int waitTimeOut,
                     List<Packet> pendingQueue,
                     ClientCnxn cnxn)
            throws IOException, InterruptedException {
        try {
            if (!firstConnect.await(waitTimeOut, TimeUnit.MILLISECONDS)) {
                return;
            }
            Packet head = null;
            if (needSasl.get()) {
                if (!waitSasl.tryAcquire(waitTimeOut, TimeUnit.MILLISECONDS)) {
                    return;
                }
            } else {
                if ((head = outgoingQueue.poll(waitTimeOut, TimeUnit.MILLISECONDS)) == null) {
                    return;
                }
            }
            // check if being waken up on closing.
            if (!sendThread.getZkState().isAlive()) {
                // adding back the patck to notify of failure in conLossPacket().
                addBack(head);
                return;
            }
            // channel disconnection happened
            if (disconnected.get()) {
                addBack(head);
                throw new EndOfStreamException("channel for sessionid 0x"
                        + Long.toHexString(sessionId)
                        + " is lost");
            }
            if (head != null) {
                doWrite(pendingQueue, head, cnxn);
            }
        } finally {
            updateNow();
        }
    }

    private void addBack(Packet head) {
        if (head != null && head != WakeupPacket.getInstance()) {
            outgoingQueue.addFirst(head);
        }
    }

    private void sendPkt(Packet p) {
        // Assuming the packet will be sent out successfully. Because if it fails,
        // the channel will close and clean up queues.
        p.createBB();
        updateLastSend();
        sentCount++;
        channel.writeAndFlush(Unpooled.wrappedBuffer(p.bb));
    }

    private void sendPrimePacket() {
        // assuming the first packet is the priming packet.
        sendPkt(outgoingQueue.remove());
    }

    /**
     * doWrite handles writing the packets from outgoingQueue via network to server.
     */
    private void doWrite(List<Packet> pendingQueue, Packet p, ClientCnxn cnxn) {
        updateNow();
        while (true) {
            if (p != WakeupPacket.getInstance()) {
                if ((p.requestHeader != null) &&
                        (p.requestHeader.getType() != ZooDefs.OpCode.ping) &&
                        (p.requestHeader.getType() != ZooDefs.OpCode.auth)) {
                    p.requestHeader.setXid(cnxn.getXid());
                    synchronized (pendingQueue) {
                        pendingQueue.add(p);
                    }
                }
                sendPkt(p);
            }
            if (outgoingQueue.isEmpty()) {
                break;
            }
            p = outgoingQueue.remove();
        }
    }

    @Override
    void sendPacket(ClientCnxn.Packet p) throws IOException {
        if (channel == null) {
            throw new IOException("channel has been closed");
        }
        sendPkt(p);
    }

    @Override
    SocketAddress getRemoteSocketAddress() {
        Channel copiedChanRef = channel;
        return (copiedChanRef == null) ? null : copiedChanRef.remoteAddress();
    }

    @Override
    SocketAddress getLocalSocketAddress() {
        Channel copiedChanRef = channel;
        return (copiedChanRef == null) ? null : copiedChanRef.localAddress();
    }

    @Override
    void testableCloseSocket() throws IOException {
        Channel copiedChanRef = channel;
        if (copiedChanRef != null) {
            copiedChanRef.disconnect().awaitUninterruptibly();
        }
    }


    // *************** <END> CientCnxnSocketNetty </END> ******************
    private static class WakeupPacket {
        private static final Packet instance = new Packet(null, null, null, null, null);

        protected WakeupPacket() {
            // Exists only to defeat instantiation.
        }

        public static Packet getInstance() {
            return instance;
        }
    }

    /**
     * ZKClientPipelineFactory is the netty pipeline factory for this netty
     * connection implementation.
     */
    private class ZKClientPipelineFactory extends ChannelInitializer<SocketChannel> {
        private SSLContext sslContext = null;
        private SSLEngine sslEngine = null;
        private String host;
        private int port;

        public ZKClientPipelineFactory(String host, int port) {
            this.host = host;
            this.port = port;
        }

        @Override
        protected void initChannel(SocketChannel ch) throws Exception {
            ChannelPipeline pipeline = ch.pipeline();
            if (clientConfig.getBoolean(ZKClientConfig.SECURE_CLIENT)) {
                initSSL(pipeline);
            }
            pipeline.addLast("handler", new ZKClientHandler());
        }

        // The synchronized is to prevent the race on shared variable "sslEngine".
        // Basically we only need to create it once.
        private synchronized void initSSL(ChannelPipeline pipeline) throws SSLContextException {
            if (sslContext == null || sslEngine == null) {
                sslContext = new ClientX509Util().createSSLContext(clientConfig);
                sslEngine = sslContext.createSSLEngine(host,port);
                sslEngine.setUseClientMode(true);
            }
            pipeline.addLast("ssl", new SslHandler(sslEngine));
            LOG.info("SSL handler added for channel: {}", pipeline.channel());
        }
    }

    /**
     * ZKClientHandler is the netty handler that sits in netty upstream last
     * place. It mainly handles read traffic and helps synchronize connection state.
     */
    private class ZKClientHandler extends SimpleChannelInboundHandler<ByteBuf> {
        AtomicBoolean channelClosed = new AtomicBoolean(false);

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            LOG.info("channel is disconnected: {}", ctx.channel());
            cleanup();
        }

        /**
         * netty handler has encountered problems. We are cleaning it up and tell outside to close
         * the channel/connection.
         */
        private void cleanup() {
            if (!channelClosed.compareAndSet(false, true)) {
                return;
            }
            disconnected.set(true);
            onClosing();
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, ByteBuf buf) throws Exception {
            updateNow();
            while (buf.isReadable()) {
                if (incomingBuffer.remaining() > buf.readableBytes()) {
                    int newLimit = incomingBuffer.position()
                            + buf.readableBytes();
                    incomingBuffer.limit(newLimit);
                }
                buf.readBytes(incomingBuffer);
                incomingBuffer.limit(incomingBuffer.capacity());

                if (!incomingBuffer.hasRemaining()) {
                    incomingBuffer.flip();
                    if (incomingBuffer == lenBuffer) {
                        recvCount++;
                        readLength();
                    } else if (!initialized) {
                        readConnectResult();
                        lenBuffer.clear();
                        incomingBuffer = lenBuffer;
                        initialized = true;
                        updateLastHeard();
                    } else {
                        sendThread.readResponse(incomingBuffer);
                        lenBuffer.clear();
                        incomingBuffer = lenBuffer;
                        updateLastHeard();
                    }
                }
            }
            wakeupCnxn();
            // Note: SimpleChannelInboundHandler releases the ByteBuf for us
            // so we don't need to do it.
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            LOG.warn("Exception caught", cause);
            cleanup();
        }
    }

    /**
     * Sets the test ByteBufAllocator. This allocator will be used by all
     * future instances of this class.
     * It is not recommended to use this method outside of testing.
     * @param allocator the ByteBufAllocator to use for all netty buffer
     *                  allocations.
     */
    public static void setTestAllocator(ByteBufAllocator allocator) {
        TEST_ALLOCATOR.set(allocator);
    }

    /**
     * Clears the test ByteBufAllocator. The default allocator will be used
     * by all future instances of this class.
     * It is not recommended to use this method outside of testing.
     */
    public static void clearTestAllocator() {
        TEST_ALLOCATOR.set(null);
    }
}
