package proxyNetwork;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

/**
 * Data Structure to keep info about proxies (IP Address and Certificates)
 */
public class ProxiesList {

    public List<ProxyInfo> proxyInfoList = new LinkedList<>();
    int size;

    public static class ProxyInfo implements Serializable {

        static final long serialVersionUID = 0L;
        public String proxyIp;
        public X509Certificate x509Certificate;

        public ProxyInfo(String ip, X509Certificate x509Certificate) {
            this.proxyIp = ip;
            this.x509Certificate = x509Certificate;
        }

        public String toString(){
            return proxyIp + " --> " + x509Certificate.getPublicKey();
        }
    }

    public ProxiesList() throws IOException {

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", Config.REGISTRY_OUT_PORT));
        try {
            proxyInfoList = (LinkedList<ProxyInfo>) new ObjectInputStream(socket.getInputStream()).readObject();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        size = proxyInfoList.size();
    }

}
