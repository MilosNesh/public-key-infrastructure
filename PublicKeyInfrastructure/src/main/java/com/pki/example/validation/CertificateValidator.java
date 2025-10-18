package com.pki.example.validation;

import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class CertificateValidator {

    public boolean isCAValid(X509Certificate caCert, X509Certificate parentOrNull) {
        try {
            // 1) Period važenja
            caCert.checkValidity();

            // 2) BasicConstraints mora biti CA
            boolean isCA = caCert.getBasicConstraints() != -1; // -1 znači nije CA
            if (!isCA) {
                System.out.println("Validator: BasicConstraints CA=false");
                return false;
            }

            // 3) KeyUsage: mora imati keyCertSign (i poželjno cRLSign)
            boolean[] ku = caCert.getKeyUsage();
            if (ku != null) {
                boolean keyCertSign = ku.length > 5 && ku[5];
                boolean cRLSign     = ku.length > 6 && ku[6];
                if (!keyCertSign) {
                    System.out.println("Validator: KeyUsage nema keyCertSign");
                    return false;
                }
                if (!cRLSign) {
                    System.out.println("Validator: (preporuka) nema cRLSign");
                }
            }

            // 4) Potpis
            if (parentOrNull != null &&
                    !caCert.getSubjectX500Principal().equals(caCert.getIssuerX500Principal())) {
                // nije self-signed -> verifikuj na parent
                caCert.verify(parentOrNull.getPublicKey());
            } else {
                // self-signed (root) -> verifikuj na sopstveni public key
                caCert.verify(caCert.getPublicKey());
            }

            // TODO: revocation (CRL/OCSP) ako želiš
            return true;

        } catch (Exception e) {
            System.out.println("Validator: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            return false;
        }
    }

    // Ako baš hoćeš staru potpis-samo-sebe varijantu za root:
    public boolean isCAValid(X509Certificate caCert) {
        return isCAValid(caCert, null);
    }

    public boolean canIssue(X509Certificate issuerCert, Date startDate, Date endDate, X509Certificate parentOrNull) {
        if (!isCAValid(issuerCert, parentOrNull)) return false;

        if (endDate.after(issuerCert.getNotAfter())) {
            System.out.println("Novi sertifikat ne može da važi duže od CA-a!");
            return false;
        }
        if (startDate.before(issuerCert.getNotBefore())) {
            System.out.println("Novi sertifikat ne može da počne pre CA-a!");
            return false;
        }
        return true;
    }
}
