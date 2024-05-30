package proxyNetwork;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The single node of proxy network.
 */
public class Proxy {

    // Always the same port to forward messages in the ProxyNetwork
    public static final Integer STANDARD_FORWARDING_PORT = 6868;
    public static final String MY_CERT = "my_proxy_cert";
    public static final String MY_PASSWORD = "my_pwd";

    public String MY_IP = "";
    private final ProxyEventLoop proxyEventLoop;

    private AtomicBoolean doAbort;
    private static AtomicInteger ipCounter = new AtomicInteger(3);
    public String localProxyKeystore;

    public static void main(String[] args) throws IOException {


        System.out.println("(Proxy Network's Proxy 1.0)");

        try {
            Proxy thirdProxy = new Proxy();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }
    public Proxy()  throws IOException, ClassNotFoundException {

        System.out.println("(Proxy Network's Proxy 1.0)");

        generateKeyAndRegisterCertificate();

        // EVENT LOOP - Listen for each client
        this.proxyEventLoop = new ProxyEventLoop();
        this.proxyEventLoop.start(this);


    }

    private void generateKeyAndRegisterCertificate() throws IOException {

        Integer myCounter = ipCounter.incrementAndGet();
        this.MY_IP = "127.0.0." + myCounter;
        System.out.println("IP Address: " + this.MY_IP);

        this.localProxyKeystore = "myKeyStore" + myCounter;
        CryptoModule.createKeyStore(localProxyKeystore);
        X509Certificate x509Certificate = CryptoModule.generateAndStoreX509Certificate(
                this.MY_IP,
                Proxy.MY_CERT,
                Proxy.MY_PASSWORD,
                localProxyKeystore
        );

        // Distribute key
        if (x509Certificate != null) {

            // Send to the registry server its address and public key
            Socket socket = new Socket("127.0.0.1", Config.REGISTRY_IN_PROXY_REGISTRATION_PORT, InetAddress.getByName(this.MY_IP), 0);
            if(socket.isConnected()) {

                OutputStream fout = socket.getOutputStream();
                ObjectOutputStream oout = new ObjectOutputStream(fout);

                ProxiesList.ProxyInfo proxyInfo = new ProxiesList.ProxyInfo(MY_IP, x509Certificate);
                oout.writeObject(proxyInfo);

                oout.flush();
                oout.close();
                fout.close();
            }

        }

    }

    /**
     * Stop the event loop
     */
    public void stopEventLoop(){
        this.proxyEventLoop.doAbort.set(true);
    }

}
