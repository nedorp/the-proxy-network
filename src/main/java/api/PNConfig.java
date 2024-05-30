package api;

import java.security.PublicKey;

/**
 * Client Config for the Anonymizing route
 */
public class PNConfig {

    // Destination address
    public String IPAddress;
    public Integer port;

    // Security Params
    public PublicKey destinationPublicKey;

    // Number of proxies to pass through
    public int routeSteps;
}
