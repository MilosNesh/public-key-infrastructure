package com.pki.example.util;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

public class CertificateUtils {

    public static boolean issuerHasChildren(X509Certificate issuerCert, String keystorePath, char[] keystorePassword) {
        try {
            List<X509Certificate> allCerts = new ArrayList<>();
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(fis, keystorePassword);

                Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    java.security.cert.Certificate[] certChain = ks.getCertificateChain(alias);
                    if (certChain != null) {
                        for (java.security.cert.Certificate c : certChain) {
                            if (c instanceof X509Certificate) {
                                allCerts.add((X509Certificate) c);
                            }
                        }
                    } else {
                        java.security.cert.Certificate c = ks.getCertificate(alias);
                        if (c instanceof X509Certificate) {
                            allCerts.add((X509Certificate) c);
                        }
                    }
                }
            }

            // Provera da li issuer ima child-a
            return allCerts.stream().anyMatch(c ->
                    c.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal()) &&
                            !c.getSerialNumber().equals(issuerCert.getSerialNumber())
            );

        } catch (Exception e) {
            throw new RuntimeException("Greška pri proveri child sertifikata: " + e.getMessage(), e);
        }
    }


    public static String getPublicKeyPEM(String certificatePath) throws Exception {
        // 1. Učitaj sertifikat iz DER fajla
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certificatePath)) {
            X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);

            // 2. Izvuci javni ključ
            PublicKey publicKey = cert.getPublicKey();

            // 3. Pretvori javni ključ u Base64
            String base64Key = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            // 4. Formatiraj kao PEM
            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.append("-----BEGIN PUBLIC KEY-----\n");

            // dodaj po 64 karaktera po liniji (standardno)
            for (int i = 0; i < base64Key.length(); i += 64) {
                int end = Math.min(i + 64, base64Key.length());
                pemBuilder.append(base64Key, i, end).append("\n");
            }

            pemBuilder.append("-----END PUBLIC KEY-----\n");

            return pemBuilder.toString();
        }
    }
}
