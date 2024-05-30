package proxyNetwork;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.*;
import java.security.PrivateKey;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;


/**
 * Event loop. Accept connections, read and write
 * correlation attacks. Nel caso introdurre messaggi fuffa per confondere, vedi vuvuzela
 */
public class ProxyEventLoop {

    private static final int BACKLOG = 80;
    private static final boolean IS_GARLIC_ENABLED = false;

    private final int SELECT_TIMEOUT = 1000;
    private ExecutorService callbackExecutor = Executors.newFixedThreadPool(2);
    public Proxy proxyRef;

    private ServerSocketChannel clientEndpoint;
    AtomicBoolean doAbort;
    public ConcurrentHashMap<SocketChannel, Integer> readySockets = new ConcurrentHashMap<>();
    public ConcurrentHashMap<SocketChannel, ObjectInputStream> openInputStreams = new ConcurrentHashMap<>();
    public ConcurrentHashMap<SocketChannel, ObjectOutputStream> openOutputStreams = new ConcurrentHashMap<>();

    // Used to group messages destinated to different relays batching them for garlic routing
    private Sink sink;

    public void start(Proxy ref) throws IOException, ClassNotFoundException {


        proxyRef = ref;
        if(IS_GARLIC_ENABLED)
            sink = new Sink(InetAddress.getByName(this.proxyRef.MY_IP));
        clientEndpoint = ServerSocketChannel.open();

        // Bind mobiles endpoint
        InetSocketAddress address = new InetSocketAddress(proxyRef.MY_IP, proxyRef.STANDARD_FORWARDING_PORT);
        clientEndpoint.bind(address, BACKLOG);
        clientEndpoint.configureBlocking(false);

        // Prepare for select
        Selector selector = Selector.open();
        SelectionKey clientsEndpointKey = clientEndpoint.register(selector, SelectionKey.OP_ACCEPT);

        doAbort = new AtomicBoolean(false);

        while(!doAbort.get()) {

            // Add readySockets
            readySockets.forEach((channel, op) -> {
                try {
                    channel.register(selector, op);
                } catch (ClosedChannelException e) {
                    e.printStackTrace();
                }
                readySockets.remove(channel);
            });

            // Blocking select
            selector.select(SELECT_TIMEOUT);

            Set<SelectionKey> selectedKeys = selector.selectedKeys();

            Iterator<SelectionKey> keyIterator = selectedKeys.iterator();

            while(keyIterator.hasNext()) {

                SelectionKey key = keyIterator.next();

                // Mobiles request accept
                if(key == clientsEndpointKey){

                    SocketChannel socketChannel = clientEndpoint.accept();
                    addStreams(socketChannel);

                    System.out.println(this.proxyRef.MY_IP + ": connessione ricevuta da " + socketChannel.getRemoteAddress());

                    // Prepare mobile socket for select
                    socketChannel.configureBlocking(false);
                    socketChannel.register(selector, SelectionKey.OP_READ);


                }

                // Client stuff
                if(key.isReadable()){

                    SocketChannel socketChannel = (SocketChannel) key.channel();
                    unregisterKey(key);

                    ObjectInputStream inputStream = openInputStreams.get(socketChannel);

                    if(inputStream == null) {
                        inputStream = new ObjectInputStream(Channels.newInputStream(socketChannel));
                        openInputStreams.put(socketChannel, inputStream);
                    }

                    // Read data
                    ObjectInputStream finalInputStream = inputStream;

                    callbackExecutor.execute(() -> {

                        try {

                            PNMessage message = (PNMessage) finalInputStream.readObject();
                            if (message.isABatch()) {

                                System.out.println("GARLIC MODE");
                                List<RouteStepChunk> messagesGarlic = message.batchOfMessages;
                                for (RouteStepChunk routeStepChunk : messagesGarlic) {

                                    // Unwrap, Store and delay the message
                                    RouteStepChunk parsedMessage = unwrapMessage(routeStepChunk);
                                    sink.receiveMessage(parsedMessage);
                                }

                            } else {

                                if (IS_GARLIC_ENABLED) {

                                    //System.out.println("GARLIC MODE");
                                    // Unwrap, Store and delay the message
                                    RouteStepChunk parsedMessage = unwrapMessage(message.singleRouteStepChunk);
                                    sink.receiveMessage(parsedMessage);

                                } else {

                                    //System.out.println("NON GARLIC MODE");
                                    // Unwrap and forward immediately (no delay)
                                    RouteStepChunk unwrappedMessage = unwrapMessage(message.getSingleMessage());
                                    RouteStepChunk.forward(unwrappedMessage, InetAddress.getByName(this.proxyRef.MY_IP));
                                }
                            }

                        } catch (IOException | ClassNotFoundException e) {
                            e.printStackTrace();
                        }

                    });

                }

                keyIterator.remove();

            }

        }

    }

    /**
     * UnWrap the message for this step
     * @param receivedMessage message received from the network
     * @return
     */
    private RouteStepChunk unwrapMessage(RouteStepChunk receivedMessage) {

        try {

            // Extract the private key from the local keystore
            PrivateKey privateKey = CryptoModule.getPrivateKey(proxyRef.localProxyKeystore, Proxy.MY_CERT, Proxy.MY_PASSWORD);
            return RouteStepChunk.unpackIntermediateLevel(receivedMessage, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;

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

    private static void unregisterKey(SelectionKey key) throws IOException {

        SocketChannel channel = (SocketChannel) key.channel();
        key.cancel();
        channel.configureBlocking(true);
    }

}
