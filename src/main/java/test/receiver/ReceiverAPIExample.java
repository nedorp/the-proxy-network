package test.receiver;

import api.PNAPIServerEndpoint;

import java.io.*;
import java.security.*;

/**
 * Receiver API Sample
 */
public class ReceiverAPIExample {

    public static String RECEIVER_PUBLIC_KEY_FILENAME = "receiverKey";
    private static int RSA_KEY_SIZE = 2048;
    public static String IP_ADDRESS = "127.0.0.1";
    public static int PORT = 9999;

    private static KeyPairGenerator getKeyGenerator(){

        // Refresh KeyPairGenerator
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(RSA_KEY_SIZE, random);
            return keyGen;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) throws IOException {

        // Create the Receiver Key Pair
        KeyPairGenerator keyGenerator = getKeyGenerator();


        if (keyGenerator != null) {

            // Generate KeyPair
            KeyPair pair = keyGenerator.generateKeyPair();

            PrivateKey myPrivateKey = pair.getPrivate();
            PublicKey pub = pair.getPublic();

            // Register Receiver Public Key (local file for test)
            FileOutputStream fout = new FileOutputStream(new File(RECEIVER_PUBLIC_KEY_FILENAME));
            ObjectOutputStream oout = new ObjectOutputStream(fout);
            oout.writeObject(pub);
            oout.flush();
            oout.close();

            // --------------------
            // Use of API (Server)
            // --------------------

            PNAPIServerEndpoint endpoint = new PNAPIServerEndpoint();
            endpoint.registerHandler(IP_ADDRESS, PORT, (messageObj) -> {

                String message = (String) messageObj;
                System.out.println("Received message: " + message);

            }, myPrivateKey);

            endpoint.start();

        }

    }
}
