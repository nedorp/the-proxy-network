package proxyNetwork;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;

import javax.crypto.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.stream.Stream;

/**
 * Cryptography Module Utility Functions
 */
public class CryptoModule {

    // CA Certification Authority Key Store
    private static final String CAKeyStoreFile = "CAKeyStore";

    // Password di test
    private static char[] keyStorePassword = "keystorepwd".toCharArray();
    private static String CAAlias = "PN_CA_CERT";
    public static String CAKeyStore = "CAKeyStore";

    /**
     * Get RSA Key Pair. Used by proxies to generate their keys. Private kept, Public distributed
     */
    public static KeyPair getRSAKeyPair() {

        try {

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.genKeyPair();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;

        }
    }

    /**
     * Encrypt the new generated secret key with the public key
     * @param proxyKey key to use to encrypt the generated secret key
     * @param secretKey key to be encrypted
     * @return the encrypted object
     */
    public static SealedObject encryptSecretKeyWithPublicKey(PublicKey proxyKey, SecretKey secretKey) {

        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, proxyKey);
            return new SealedObject(secretKey, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | IOException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }


    }

    /**
     * Get the symmetric key to encrypt inner level of the message
     * @return the symmetric key
     */
    public static SecretKey getNewSecretKey() {
        try {
            return KeyGenerator.getInstance("AES").generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Encrypt the serializable object with the symmetric key
     * @param secretKey symmetric key
     * @param object to be encrypted
     * @return the encrypted result
     */
    public static SealedObject encryptObjectWithSymmetricKey(SecretKey secretKey, Serializable object) {
        try {

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return new SealedObject(object, cipher);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Test function. To generate certificate for proxies
     * Credentials per CA Certificate: alias: PN_CA_CERT password: pncacert
     * TEST: Each proxy when started will generate a certificate guaranteed by the local CA
     */
    public static X509Certificate generateAndStoreX509Certificate(String CNidentifier, String alias, String password, String keyStoreFile){

        // Synchronized only for Testing purposes. The KeyStore can be accessed only by one thread at the same time
        synchronized (CryptoModule.class) {

            KeyStore keyStore = loadKeystore(keyStoreFile);
            if (keyStore == null)
                return null;

            // generate the certificate
            // first parameter  = Algorithm
            // second parameter = signature algorithm
            // third parameter  = the provider to use to generate the keys (may be null or
            //                    use the constructor without provider)
            CertAndKeyGen certGen = null;
            try {
                certGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
                // generate it with 2048 bits
                certGen.generate(2048);

                // prepare the validity of the certificate
                long validSecs = (long) 365 * 24 * 60 * 60; // valid for one year
                // add the certificate information, currently only valid for one year.
                X509Certificate cert = certGen.getSelfCertificate(
                        // enter your details according to your application
                        new X500Name("CN=ProxyNetwork" + CNidentifier + ",O=org.test.proxyNetwork,L=Italy,C=IT"), validSecs);

                // set the certificate and the key in the keystore
                keyStore.setKeyEntry(alias, certGen.getPrivateKey(), password.toCharArray(),
                        new X509Certificate[]{cert});

                // Per leggere il certificato della CA: System.out.println(keyStore.getCertificate("PN_CA_CERT"));

                storeKeystore(keyStore, keyStoreFile);

                return cert;
            } catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateException | IOException | SignatureException | InvalidKeyException | KeyStoreException e) {
                e.printStackTrace();
                return null;
            }
        }
    }

    /**
     * Sign certificate with CA Certificate
     * @param toBeSignedCertificate  certificate to be signed
     * @param CAKeyStore store of the CA
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     */
    public static X509CertImpl signCertificateByCA(X509Certificate toBeSignedCertificate, String CAKeyStore) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {

        // Synchronized only for Testing purposes. The KeyStore can be accessed only by one thread at the same time
        synchronized (CryptoModule.class) {

            KeyStore keyStore = loadKeystore(CAKeyStore);

            char[] realPwd = "pncacert".toCharArray();
            PrivateKey caPrivateKey = (PrivateKey) keyStore.getKey(CryptoModule.CAAlias, realPwd);
            java.security.cert.Certificate caCert = keyStore.getCertificate(CryptoModule.CAAlias);

            byte[] encoded = caCert.getEncoded();
            X509CertImpl caCertImpl = new X509CertImpl(encoded);

            X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "."
                    + X509CertImpl.INFO);

            X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "."
                    + CertificateIssuerName.DN_NAME);

            encoded = toBeSignedCertificate.getEncoded();
            X509CertImpl certImpl = new X509CertImpl(encoded);
            X509CertInfo certInfo = (X509CertInfo) certImpl
                .get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

            Date firstDate = new Date();
            Date lastDate = new Date(firstDate.getTime() + 365 * 24 * 60 * 60 * 1000L);
            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);

            certInfo.set(X509CertInfo.VALIDITY, interval);

            certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
                (int) (firstDate.getTime() / 1000)));

            certInfo.set(X509CertInfo.ISSUER + "." + CertificateSubjectName.DN_NAME, issuer);

            AlgorithmId algorithm = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);
            certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithm);
            X509CertImpl newCert = new X509CertImpl(certInfo);

            newCert.sign(caPrivateKey, "SHA256WithRSA");
            return newCert;

        }
    }

    /**
     * List all stored keys alias for the specified key store
     * @param keyStoreFile
     */
    public static void listAllStoredKeys(String keyStoreFile){

        // Synchronized only for Testing purposes. The KeyStore can be accessed only by one thread at the same time
        synchronized (CryptoModule.class) {

            KeyStore keyStore = null;
            try {

                keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

                // Store away the keystore.
                FileInputStream fin = new FileInputStream(keyStoreFile);
                keyStore.load(fin, CryptoModule.keyStorePassword);
                fin.close();

                Enumeration<String> aliases = keyStore.aliases();
                /*while(aliases.hasMoreElements()) {
                    System.out.println(aliases.nextElement());
                }*/

            } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
                e.printStackTrace();
            }

        }

    }

    private static void generateCACertificate(){
        // generateX509Certificate("PN_CA_CERT", CAKeyStoreFile);
    }

    // ------------------
    // KeyStore Handling
    // ------------------

    /**
     * Create a file to store a KeyStore
     * @param keyStoreFile
     * @return
     */
    static KeyStore createKeyStore(String keyStoreFile) {

        KeyStore keyStore = null;// your keystore

        try {

            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, CryptoModule.keyStorePassword);
            storeKeystore(keyStore, keyStoreFile);

        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    /**
     * Load the keystore from the specified file
     * @param keyStoreFile
     * @return
     */
    static KeyStore loadKeystore(String keyStoreFile) {

        KeyStore keyStore = null;// your keystore
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

            // Load the keystore.
            FileInputStream fin = new FileInputStream(keyStoreFile);
            keyStore.load(fin, CryptoModule.keyStorePassword);
            fin.close();

            return keyStore;

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Store the KeyStore into the specified file
     * @param keyStore
     * @param keyStoreFile
     */
    private static void storeKeystore(KeyStore keyStore, String keyStoreFile) {

        // Store away the keystore.
        FileOutputStream fos;
        try {

            fos = new FileOutputStream(keyStoreFile);
            keyStore.store(fos, CryptoModule.keyStorePassword);
            fos.flush();
            fos.close();

        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

    }


    /**
     * Get PrivateKey from the alias certificate contained into the keystoreFile
     * @param keyStoreFile
     * @param alias
     * @param password
     * @return
     */
    static PrivateKey getPrivateKey(String keyStoreFile, String alias, String password) {

        KeyStore keyStore = CryptoModule.loadKeystore(keyStoreFile);
        listAllStoredKeys(keyStoreFile);
        try {
            if (keyStore != null) {
                return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
            }
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Check whether the passed Certificates are issued by the CA and the return the valid ones
     * @param signedCertificates input certificates that are obtained from the registry-server
     */
    public static void checkCertificatesWithCA(Stream<X509Certificate> signedCertificates) {

        X509Certificate CACertificate;
        try {
            CACertificate = (X509Certificate) CryptoModule.loadKeystore(CryptoModule.CAKeyStoreFile).getCertificate(CryptoModule.CAAlias);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return;
        }
        PublicKey issuerPublicKey = CACertificate.getPublicKey();

        Stream<X509Certificate> validCertificates = signedCertificates.filter(((X509Certificate x509Certificate) -> {
            try {

                x509Certificate.verify(issuerPublicKey);
                return true;
            } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
                return false;
            }
        }));

        // System.out.println(System.nanoTime() + "# Valid Certificates = " + validCertificates.toArray().length);

    }
}
