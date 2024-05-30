package proxyNetwork;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This server distributes couples <IP, Public Keys> and receives the registration of new proxies
 * Automated registration, but like every CA, it would need manual human acceptance and rejection
 */
public class RegistryServer {

    // Cached registeredProxies
    private static LinkedList<ProxiesList.ProxyInfo> registeredProxies = new LinkedList<>();

    public static void init() throws IOException, ClassNotFoundException {

        System.out.println("(Registry Server 1.0)\n\n");
        ServerSocket serverSocket = new ServerSocket(Config.REGISTRY_OUT_PORT);
        ServerSocket proxyRegistrationSocket = new ServerSocket(Config.REGISTRY_IN_PROXY_REGISTRATION_PORT);

        new Thread(() -> {
            try {

                while (true) {
                    Socket client = serverSocket.accept();
                    ObjectOutputStream objectOutputStream = new ObjectOutputStream(client.getOutputStream());
                    objectOutputStream.writeObject(registeredProxies);
                    System.out.println("Request for certificates from client");
                    objectOutputStream.flush();
                }
            } catch(Exception e) {
                System.out.println("Crashed thread for proxy list delivery");
            }
        }).start();

        while (true) {

            Socket client = proxyRegistrationSocket.accept();
            ObjectInputStream objectInputStream = new ObjectInputStream(client.getInputStream());
            ProxiesList.ProxyInfo newProxyInfo = (ProxiesList.ProxyInfo) objectInputStream.readObject();

            if(newProxyInfo != null) {
                X509Certificate signedCertificate = checkCertificateAddress(client.getRemoteSocketAddress(), newProxyInfo.x509Certificate);
                if(signedCertificate != null) {
                    newProxyInfo.x509Certificate = signedCertificate;
                    registeredProxies.add(newProxyInfo);
                }

                // System.out.println(newProxyInfo);
            }
            // System.out.println("Receiving Proxy Info ...");
            objectInputStream.close();
        }
    }

    private static X509Certificate checkCertificateAddress(SocketAddress remoteSocketAddress, X509Certificate x509Certificate) {
        String connectedIp = (((InetSocketAddress) remoteSocketAddress).getAddress()).toString().replace("/","");

        System.out.println("Join request from " + connectedIp);
        System.out.println("Declared Subject is " + x509Certificate.getSubjectX500Principal());

        // Declared IP into certificate
        String declaredIp = extractIPFromSubjectDN(x509Certificate.getSubjectX500Principal());

        if (declaredIp != null && declaredIp.equals(connectedIp)) {

            try {

                // Sign correct certificate with the CA of ProxyNetwork Private Key
                X509Certificate x509Cert = CryptoModule.signCertificateByCA(x509Certificate, CryptoModule.CAKeyStore);
                System.out.println("Correctly signed by " + x509Cert.getIssuerX500Principal().getName());
                return x509Cert;

            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | InvalidKeyException | UnrecoverableKeyException | SignatureException | NoSuchProviderException e) {
                e.printStackTrace();
            }

        } else {
            System.out.println("Invalid Certificate");
            return null;
        }

        return null;
    }

    private static String extractIPFromSubjectDN(X500Principal subjectX500Principal) {

        Pattern compile = Pattern.compile(".*(ProxyNetwork)([^,]*)"); // "/(ProxyNetwork)([^,]*)/g");
        Matcher matcher = compile.matcher(subjectX500Principal.toString());
        if(matcher.find()){
            System.out.println("Declared IP: " + matcher.group(2));
            return matcher.group(2);
        }

        return null;

    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        init();
    }
}