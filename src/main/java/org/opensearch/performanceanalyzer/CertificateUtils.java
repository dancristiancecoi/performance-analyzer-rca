/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.performanceanalyzer;


import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nullable;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.opensearch.performanceanalyzer.commons.config.PluginSettings;

public class CertificateUtils {

    public static final String ALIAS_IDENTITY = "identity";
    public static final String ALIAS_CERT = "cert";
    // The password is not used to encrypt keys on disk.
    public static final String IN_MEMORY_PWD = "opendistro";
    public static final String CERTIFICATE_FILE_PATH = "certificate-file-path";
    public static final String PRIVATE_KEY_FILE_PATH = "private-key-file-path";
    public static final String TRUSTED_CAS_FILE_PATH = "trusted-cas-file-path";
    public static final String CLIENT_PREFIX = "client-";
    public static final String CLIENT_CERTIFICATE_FILE_PATH = CLIENT_PREFIX + CERTIFICATE_FILE_PATH;
    public static final String CLIENT_PRIVATE_KEY_FILE_PATH = CLIENT_PREFIX + PRIVATE_KEY_FILE_PATH;
    public static final String CLIENT_TRUSTED_CAS_FILE_PATH = CLIENT_PREFIX + TRUSTED_CAS_FILE_PATH;

    private static final Logger LOGGER = LogManager.getLogger(CertificateUtils.class);

    public static Certificate getCertificate(final FileReader certReader) throws Exception {
        try (PEMParser pemParser = new PEMParser(certReader)) {
            X509CertificateHolder certificateHolder =
                    (X509CertificateHolder) pemParser.readObject();
            Certificate caCertificate =
                    new JcaX509CertificateConverter()
                            .setProvider("BC")
                            .getCertificate(certificateHolder);
            return caCertificate;
        }
    }

    public static byte[] readPrivateKey(String keyFilePath) throws KeyException {
        try (FileReader in = new FileReader(keyFilePath)) {
            try (PemReader pemReader = new PemReader(in)) {
                PemObject pemObject = pemReader.readPemObject();
                if (pemObject == null) {
                    throw new KeyException("could not read the private key");
                }
                return pemObject.getContent();
            }

        } catch (IOException e) {
            throw new KeyException("could not read the private key", e);
        }
    }

    public static PrivateKey generatePrivateKey(EncodedKeySpec encodedKeySpec)
            throws InvalidKeySpecException {
        List<String> algorithms = Arrays.asList("RSA", "DSA", "EC");
        PrivateKey privateKey = null;
        for (String algorithm : algorithms) {
            try {
                privateKey = KeyFactory.getInstance(algorithm).generatePrivate(encodedKeySpec);
                break;
            } catch (InvalidKeySpecException | NoSuchAlgorithmException ignored) {
                // try the next algorithm
                LOGGER.log(
                        Level.INFO, "Failed to generate private key with algorithm: " + algorithm);
            }
        }
        if (privateKey == null) {
            throw new InvalidKeySpecException("Neither RSA, DSA nor EC worked");
        }
        return privateKey;
    }

    public static KeyStore createKeyStore() throws Exception {
        String certFilePath = PluginSettings.instance().getSettingValue(CERTIFICATE_FILE_PATH);
        String keyFilePath = PluginSettings.instance().getSettingValue(PRIVATE_KEY_FILE_PATH);
        KeyStore.ProtectionParameter protParam =
                new KeyStore.PasswordProtection(CertificateUtils.IN_MEMORY_PWD.toCharArray());
        byte[] fileByte = readPrivateKey(keyFilePath);
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(fileByte);
        PrivateKey privateKey = generatePrivateKey(encodedKeySpec);
        KeyStore ks = createEmptyStore();
        Certificate certificate = getCertificate(new FileReader(certFilePath));
        ks.setEntry(
                ALIAS_IDENTITY,
                new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] {certificate}),
                protParam);
        return ks;
    }

    public static TrustManager[] getTrustManagers(boolean forServer) throws Exception {
        // If a certificate authority is specified, create an authenticating trust manager
        String certificateAuthority;
        if (forServer) {
            certificateAuthority = PluginSettings.instance().getSettingValue(TRUSTED_CAS_FILE_PATH);
        } else {
            certificateAuthority =
                    PluginSettings.instance().getSettingValue(CLIENT_TRUSTED_CAS_FILE_PATH);
        }
        if (certificateAuthority != null && !certificateAuthority.isEmpty()) {
            KeyStore ks = createEmptyStore();
            Certificate certificate = getCertificate(new FileReader(certificateAuthority));
            ks.setCertificateEntry(ALIAS_CERT, certificate);
            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            return tmf.getTrustManagers();
        }
        // Otherwise, return an all-trusting TrustManager
        return new TrustManager[] {
            new X509TrustManager() {

                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {}

                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
    }

    public static KeyStore createEmptyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, IN_MEMORY_PWD.toCharArray());
        return ks;
    }

    public static File getCertificateFile() {
        String certFilePath = PluginSettings.instance().getSettingValue(CERTIFICATE_FILE_PATH);
        return new File(certFilePath);
    }

    public static File getPrivateKeyFile() {
        String privateKeyPath = PluginSettings.instance().getSettingValue(PRIVATE_KEY_FILE_PATH);
        return new File(privateKeyPath);
    }

    @Nullable
    public static File getTrustedCasFile() {
        String trustedCasPath = PluginSettings.instance().getSettingValue(TRUSTED_CAS_FILE_PATH);
        if (trustedCasPath == null || trustedCasPath.isEmpty()) {
            return null;
        }
        return new File(trustedCasPath);
    }

    public static File getClientCertificateFile() {
        String certFilePath =
                PluginSettings.instance().getSettingValue(CLIENT_CERTIFICATE_FILE_PATH);
        if (certFilePath == null || certFilePath.isEmpty()) {
            return getCertificateFile();
        }
        return new File(certFilePath);
    }

    public static File getClientPrivateKeyFile() {
        String privateKeyPath =
                PluginSettings.instance().getSettingValue(CLIENT_PRIVATE_KEY_FILE_PATH);
        if (privateKeyPath == null || privateKeyPath.isEmpty()) {
            return getPrivateKeyFile();
        }
        return new File(privateKeyPath);
    }

    @Nullable
    public static File getClientTrustedCasFile() {
        String trustedCasPath =
                PluginSettings.instance().getSettingValue(CLIENT_TRUSTED_CAS_FILE_PATH);
        // By default, use the same CA as the server
        if (trustedCasPath == null || trustedCasPath.isEmpty()) {
            return getTrustedCasFile();
        }
        return new File(trustedCasPath);
    }
}
