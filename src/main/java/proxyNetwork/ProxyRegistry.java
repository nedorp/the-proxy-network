package proxyNetwork;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.*;

/**
 * Local Registry for proxyNetwork routing of messages.
 * At init phase will load proxy certificates from the Global Registry Server
 */
public class ProxyRegistry {

    private LinkedList<ProxiesList.ProxyInfo> proxyInfoList = new LinkedList<>();
    private int size;

    public ProxyRegistry() throws IOException {

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", Config.REGISTRY_OUT_PORT));
        try {
            proxyInfoList = (LinkedList<ProxiesList.ProxyInfo>) new ObjectInputStream(socket.getInputStream()).readObject();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        size = proxyInfoList.size();
        System.out.println("Taking " + size + " available certificates");
        CryptoModule.checkCertificatesWithCA(proxyInfoList.stream().map(
                (proxyInfo) -> proxyInfo.x509Certificate)
        );
    }

    /**
     * Choose the steps for the path throught the Proxy Network
     * @param n number of steps for routing
     * @return
     */
    public List<ProxiesList.ProxyInfo> chooseNSteps(int n){

        SecureRandom random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            random.setSeed(System.currentTimeMillis() % 1000);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }

        ArrayList<ProxiesList.ProxyInfo> chosenProxiesList = new ArrayList<>(n);
        LinkedList<ProxiesList.ProxyInfo> proxyInfoList = this.proxyInfoList;

        HashSet<Integer> proxies = new HashSet<>();

        // Applicare controllo affinchè il proxyNetwork non rinvii a sè stesso il voto
        while (proxies.size() < n) {

            int proxyIndex = (int) Math.round(random.nextDouble()*(size-1));
            if (!proxies.contains(proxyIndex)) {

                // Add Index for check
                proxies.add(proxyIndex);

                // Add proxy for encryption
                ProxiesList.ProxyInfo proxyInfo = proxyInfoList.get(proxyIndex);
                chosenProxiesList.add(proxyInfo);
                System.out.println("Choosing proxy: " + proxyInfo.proxyIp);
            }

        }

        return chosenProxiesList;

    }

}
