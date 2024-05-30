package test.client;

import api.PNAPIClientEndpoint;
import api.PNConfig;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.PublicKey;

import static test.receiver.ReceiverConfig.IP_ADDRESS;
import static test.receiver.ReceiverConfig.PORT;
import static test.receiver.ReceiverConfig.RECEIVER_PUBLIC_KEY_FILENAME;

/**
 * Client API Sample
 */
public class ClientAPIExample {

    public static void main(String[] args) throws IOException {

        // Load receiver public key
        FileInputStream fis = null;

        // Load Receiver Public Key
        fis = new FileInputStream(RECEIVER_PUBLIC_KEY_FILENAME);
        ObjectInputStream oin = new ObjectInputStream(fis);

        PublicKey receiverKey = null;
        try {
            receiverKey = (PublicKey) oin.readObject();
        } catch(IOException | ClassNotFoundException e ){
            System.out.println("Failed in reading public key of receiver");
            e.printStackTrace();
            return;
        }

        // --------------------
        // Use of API (Client)
        // --------------------

        PNConfig config = new PNConfig();
        config.destinationPublicKey = receiverKey;
        config.IPAddress = IP_ADDRESS;
        config.port = PORT;
        config.routeSteps = 5;

        PNAPIClientEndpoint client = new PNAPIClientEndpoint(config);
        client.sendMessage("Onion routing is a technique for anonymous communication over a computer network. In an " +
                "onion network, messages are encapsulated in layers of encryption, analogous " +
                "to layers of an onion.");

        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
