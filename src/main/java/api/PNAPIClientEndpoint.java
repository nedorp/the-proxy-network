package api;

import proxyNetwork.*;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.security.PublicKey;
import java.util.List;

/**
 * API Interface to use the proxy network to guarantee anonimity, onion/garlic routing
 */
public class PNAPIClientEndpoint {

    /**
     * Local registry fed with Global Registry Server information
     */
    private ProxyRegistry proxyRegistry;

    // Destination Info
    private String destinationIP;
    private Integer destinationPort;
    private final PublicKey destinationPublicKey;

    // Config
    private int routeSteps;


    /**
     * Constructor (pass the configuration)
     * @param config config for
     */
    public PNAPIClientEndpoint(PNConfig config) throws IOException {

        this.destinationIP = config.IPAddress;
        this.destinationPort = config.port;
        this.destinationPublicKey = config.destinationPublicKey;
        this.routeSteps = config.routeSteps;

        this.proxyRegistry = new ProxyRegistry();

    }

    /**
     * Send a serializable object throught the Proxy Network towards the Receiver with specified destination IP and port
     * @param message a serializable object. Both receiver and client needs to agree on application protocol
     */
    public void sendMessage(Serializable message){

            try {

                List<ProxiesList.ProxyInfo> chosenProxies = proxyRegistry.chooseNSteps(this.routeSteps);

                // First Proxy
                ProxiesList.ProxyInfo firstProxy = chosenProxies.get(chosenProxies.size() - 1);

                RouteStepChunk wrappedMessage = RouteStepChunk.createEnvelopPacket(
                        chosenProxies,
                        message,
                        this.destinationIP,
                        this.destinationPort,
                        this.destinationPublicKey
                );
                System.out.println("Message: " + message);

                PNMessage pnMessage = PNMessage.getSingleChunkRouteMessage(wrappedMessage);

                // Start the routing of the wrapped message
                Socket toFirstProxy = new Socket(firstProxy.proxyIp, Proxy.STANDARD_FORWARDING_PORT);
                ObjectOutputStream out = new ObjectOutputStream(toFirstProxy.getOutputStream());

                // Send message through socket
                out.writeObject(pnMessage);
                out.flush();

            } catch (IOException e){
                System.out.println("Failed send");
        }
    }

}

