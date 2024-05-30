package proxyNetwork;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * Chunk of the shell(onion) of info for the pseudo-anonymous (from the external observer) routing of the message
 * Encrypt the message with the Receiver public key, then encrypt with the last proxy key and add the IP of it
 * Then encrypt with the penultimate proxy key etc.
 */
public class RouteStepChunk implements Serializable {

    static final long serialVersionUID = 0L;

    /** IP of the proxy */
    private String IP;

    /** Optional port */
    private Integer port;

    /** This contains the secretKey encrypted with the publicKey of the node with the above IP */
    private SealedObject secretKey;

    /** This is the next routing step, it's encrypted with the above secretKey */
    private SealedObject innerLevel;

    public static RouteStepChunk createEnvelopPacket(List<ProxiesList.ProxyInfo> proxyInfo, Serializable message, String destinationAddress, Integer port, PublicKey receiverKey){

        RouteStepChunk stepChunk = null;

        for(int step = 0; step < proxyInfo.size(); step++){

            ProxiesList.ProxyInfo current = proxyInfo.get(step);
            if(step == 0){

                // Create deepest level (lastStep)
                String lastIP = current.proxyIp;

                /** Here you pass the message. Encrypt by Receiver Key, then encrypt by lastStep proxy Key*/
                RouteStepChunk receiverEncryptedMessage = new RouteStepChunk(destinationAddress, receiverKey,  message, port);
                stepChunk = new RouteStepChunk(lastIP, current.x509Certificate.getPublicKey(), receiverEncryptedMessage, null);
            }
            else {
                stepChunk = new RouteStepChunk(current.proxyIp, current.x509Certificate.getPublicKey(), stepChunk,null);
            }

        }

        // This is the chain of chunks
        return stepChunk;

    }

    /** Constructor for each step */
    private RouteStepChunk(String IP, PublicKey proxyKey, Serializable innerLevelContent, Integer port) {

        this.IP = IP;
        this.port = (port != null)? port : Proxy.STANDARD_FORWARDING_PORT;
        SecretKey newSecretKey = CryptoModule.getNewSecretKey();
        this.secretKey = CryptoModule.encryptSecretKeyWithPublicKey(proxyKey, newSecretKey);
        //System.out.println("Creo la secret key simmetrica e la encripto -> " + newSecretKey.hashCode());
        this.innerLevel = CryptoModule.encryptObjectWithSymmetricKey(newSecretKey, innerLevelContent);
        //System.out.println("Encripto tutto con la nuova chiave " + newSecretKey.hashCode());

    }

    /** Forward the unwrapped message to the next step */
    public static SealedObject forward(RouteStepChunk unwrappedMessage, InetAddress myAddress) {

        // get the symmetric key and unpack
        try {

            System.out.println("Forwarding to " + unwrappedMessage.IP);

            Socket toForwardSocket = new Socket(unwrappedMessage.IP, unwrappedMessage.port, myAddress, 0);
            if(toForwardSocket.isConnected()){

                // Send to other proxy
                ObjectOutputStream toBrotherOut = new ObjectOutputStream(toForwardSocket.getOutputStream());

                toBrotherOut.writeObject(PNMessage.getSingleChunkRouteMessage(unwrappedMessage));
            }
            else {
                System.out.println("Not Connected!");
            }

            return null;

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Used by the edge receiver
     * @param wrappedMessage
     * @param key
     * @return
     */
    public static Object unpack(RouteStepChunk wrappedMessage, PrivateKey key) {

        try {

            SecretKey symmetricKey = (SecretKey) wrappedMessage.secretKey.getObject(key);
            return wrappedMessage.innerLevel.getObject(symmetricKey);

        } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     *
     * @return
     */
    String getIP(){
        return IP;
    }
    Integer getPort(){ return port; }

    static RouteStepChunk unpackIntermediateLevel(RouteStepChunk wrappedMessage, PrivateKey privateKey) {

        try {
            SecretKey symmetricKey = (SecretKey) wrappedMessage.secretKey.getObject(privateKey);
            return (RouteStepChunk) wrappedMessage.innerLevel.getObject(symmetricKey);
        } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

    }
}

