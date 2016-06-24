package tfg.prove.router;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import java.net.MalformedURLException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.logging.Logger;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.IOException;

public class HTTPSClient {

    private String HTTPS_URL = "https://localhost:4000";
    private String KEY_STORE_FILE="C:/certs/routerXBee_KeyStore.pkcs12";
    private String KEY_STORE_PASS="ivanfa";
    private String TRUST_STORE_FILE="C:/certs/ca/TrustStoreXBee";
    private String TRUST_STORE_PASS="ivanfa";

    //Documented in security guides (Under "Standard Names") on both Java 7 VMs
    /** Oracle VM valid values
     *  - SunX509
     *  IBM VM valid values
     *  - IbmX509
     */
    private String KEY_MANAGER_ALGORITHM = "SunX509";
    /** Oracle VM valid values
     *  - PKCS12, JKS
     *  IBM VM valid values
     *  - PKCS12, JKS, JCEKS
     */
    private String KEY_STORE_FORMAT = "PKCS12";
    private String TRUST_STORE_FORMAT = "JKS";

    /** Oracle VM valid values
     *  - PKIX
     *  IBM VM valid values
     *  - PKIX or IbmPKIX or IbmX509
     */
    private String TRUST_MANAGER_ALGORITHM="PKIX";

    /** Oracle VM valid values
     *  - SSL SSLv2 SSLv3 TLS TLSv1 TLSv1.1 TLSv1.2
     *  IBM VM valid values
     *  - SSL SSLv3 TLS_SSL TLS TLSv1
     */
    // Oracle VM
    private String SSL_CONTEXT_ALGORITHM = "TLS";

    private final static Logger logger = Logger.getLogger(HTTPSClient.class.getName());
	static {
	    //for localhost testing only
	    javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
	    new javax.net.ssl.HostnameVerifier(){

	        public boolean verify(String hostname,
	                javax.net.ssl.SSLSession sslSession) {
	            if (hostname.equals("localhost")) {
	                return true;
	            }
	            return false;
	        }
	    });
	}

    public static void main(String[] args) {
        new HTTPSClient().connect();
    }

    private void connect() {

        try {
            URL url = new URL(HTTPS_URL);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
            	    new javax.net.ssl.HostnameVerifier(){

            	        public boolean verify(String hostname,
            	                javax.net.ssl.SSLSession sslSession) {
            	            if (hostname.equals("localhost")) {
            	                return true;
            	            }
            	            return false;
            	        }
            	    });
            conn.setSSLSocketFactory(getFactory(new File(KEY_STORE_FILE), KEY_STORE_PASS, new File(TRUST_STORE_FILE), TRUST_STORE_PASS));
            conn.connect();
            Certificate[] certs = conn.getServerCertificates();

            if (conn != null) {
                for (Certificate cert : certs) {
                    logger.info("Cert Type: " + cert.getType());
                    logger.info("Cert Hash Code: " + cert.hashCode());
                    logger.info("Cert Algorithm: " + cert.getPublicKey().getAlgorithm());
                    logger.info("Cert Format: " + cert.getPublicKey().getFormat());
                }
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;

            while ((line=br.readLine()) != null) {
                logger.info (line);
            }

            br.close();

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private SSLSocketFactory getFactory(File pKeyFile, String pKeyPassword, File pTrustStoreFile, String pTrustStorePassword) {

        SSLSocketFactory socketFactory = null;

        try {

            KeyManagerFactory keyManagerFactory;
            keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_ALGORITHM);
            KeyStore keyStore;
            keyStore = KeyStore.getInstance(KEY_STORE_FORMAT);
            InputStream keyInput = new FileInputStream(pKeyFile);
            keyStore.load(keyInput, pKeyPassword.toCharArray());
            keyInput.close();
            keyManagerFactory.init(keyStore, pKeyPassword.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TRUST_MANAGER_ALGORITHM);
            KeyStore trustStore;
            trustStore = KeyStore.getInstance(TRUST_STORE_FORMAT);
            if(!pTrustStoreFile.canRead())pTrustStoreFile.setReadable(true);            	
            InputStream trustStoreInput = new FileInputStream(pTrustStoreFile);
            trustStore.load(trustStoreInput, pTrustStorePassword.toCharArray());
            trustStoreInput.close();
            trustManagerFactory.init(trustStore);

            SSLContext context = SSLContext.getInstance(SSL_CONTEXT_ALGORITHM);
            context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            socketFactory=context.getSocketFactory();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return socketFactory;
    }

}