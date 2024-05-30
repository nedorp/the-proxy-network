package test;

import proxyNetwork.Proxy;

import java.io.IOException;

/**
 * Build up a simulated network of specified number of nodes
 */
public class ProxyNetworkSetupTest {

    private static final int PROXY_NET_NUMBER = 10;
    public static void main(String[] args) {

        // Setup proxies
        for(int i = 0; i < PROXY_NET_NUMBER; i++) {

            new Thread(() -> {
                try {
                    Proxy node = new Proxy();
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }
}
