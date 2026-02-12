package com.pki.example.util;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
}
