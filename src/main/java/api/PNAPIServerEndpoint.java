package api;

import proxyNetwork.PNMessage;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.nio.channels.*;
import java.security.PrivateKey;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import static proxyNetwork.RouteStepChunk.unpack;

/**
 * API for the receiver server of PN messages from clients
 */
public class PNAPIServerEndpoint {

    public String IP_ADDRESS = "127.0.0.1";
    public int PORT = 9999;
    private final int SELECT_TIMEOUT = 1000;
    private PrivateKey myPrivateKey;

    // Socket Stuff
    private ServerSocketChannel proxyEndpoint;
    private final int BACKLOG = 80;

    // Internal Stuff
    private ConcurrentHashMap<SocketChannel, Integer> readySockets = new ConcurrentHashMap<>();

    private ConcurrentHashMap<SocketChannel, ObjectInputStream> openInputStreams = new ConcurrentHashMap<>();
    private ConcurrentHashMap<SocketChannel, ObjectOutputStream> openOutputStreams = new ConcurrentHashMap<>();
    private Consumer<Object> receptionCallback;


    /**
     * Register a callback on the specified socket
     * to handle incoming messages from the Proxy Network
     * @param ipAddress address of the server endpoint
     * @param port port of the server endpoint
     * @param callback function to be executed after each reception
     */
    public void registerHandler(String ipAddress, Integer port, Consumer<Object> callback, PrivateKey privateKey) throws IOException {

        // Open endpoint for proxies to connect
        proxyEndpoint = ServerSocketChannel.open();
        InetSocketAddress address = new InetSocketAddress(ipAddress, port);

        // Bind the socket
        proxyEndpoint.bind(address, BACKLOG);
        System.out.println("(Receiver Server 1.0) - Bind successful.");
        proxyEndpoint.configureBlocking(false);

        myPrivateKey = privateKey;
        receptionCallback = callback;

    }

    /**
     * Start listening and
     * @throws IOException
     */
    public void start() throws IOException {

        // Prepare for select
        Selector selector = Selector.open();
        SelectionKey proxyEndpointKey = proxyEndpoint.register(selector, SelectionKey.OP_ACCEPT);

        while (true) {

            selector.select(SELECT_TIMEOUT);

            // Add readySockets for next Select - Select will remove cancelled keys
            readySockets.forEach((channel, op) -> {
                try {
                    channel.register(selector, op);
                } catch (ClosedChannelException e) {
                    e.printStackTrace();
                }
                readySockets.remove(channel);
            });

            Set<SelectionKey> selectedKeys = selector.selectedKeys();

            Iterator<SelectionKey> keyIterator = selectedKeys.iterator();

            while (keyIterator.hasNext()) {

                SelectionKey key = keyIterator.next();

                // Proxy request accept
                if (key == proxyEndpointKey) {

                    SocketChannel socketChannel = proxyEndpoint.accept();
                    addStreams(socketChannel);


                    // Manage Proxy Access
                    socketChannel.configureBlocking(false);
                    socketChannel.register(selector, SelectionKey.OP_READ);

                    System.out.println("Connection from: " + socketChannel.getRemoteAddress());

                }

                // Proxy stuff to be read
                else if (key.isReadable()) {

                    SocketChannel socketChannel = (SocketChannel) key.channel();
                    unregisterKey(key);

                    ObjectInputStream inputStream = openInputStreams.get(socketChannel);
                    ObjectOutputStream outputStream = openOutputStreams.get(socketChannel);

                    if (inputStream == null) {
                        inputStream = new ObjectInputStream(Channels.newInputStream(socketChannel));
                        openInputStreams.put(socketChannel, inputStream);
                    }

                    if (outputStream == null) {
                        outputStream = new ObjectOutputStream(Channels.newOutputStream(socketChannel));
                        openOutputStreams.put(socketChannel, outputStream);
                    }

                    try {


                        PNMessage message = (PNMessage) inputStream.readObject();

                        if (message.isABatch()) {

                            message.getBatchOfMessages().forEach((msg) -> {
                                receptionCallback.accept(unpack(msg, myPrivateKey));
                            });

                        } else {
                            receptionCallback.accept(unpack(message.getSingleMessage(), myPrivateKey));
                        }

                        // Reading the message
                        // SealedObject message = (SealedObject) inputStream.readObject();
                    } catch (ClassNotFoundException /*| NoSuchAlgorithmException | InvalidKeyException*/ e) {
                        e.printStackTrace();
                    }

                    socketChannel.configureBlocking(false);
                    readySockets.put(socketChannel, SelectionKey.OP_READ);
                }

                keyIterator.remove();
            }
        }
    }

    private void addStreams(SocketChannel socketChannel) {

        try {
            openInputStreams.put(socketChannel, new ObjectInputStream(Channels.newInputStream(socketChannel)));
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            openOutputStreams.put(socketChannel, new ObjectOutputStream(Channels.newOutputStream(socketChannel)));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private void unregisterKey(SelectionKey key) throws IOException {

        SocketChannel channel = (SocketChannel) key.channel();
        key.cancel();
        channel.configureBlocking(true);
    }


}
