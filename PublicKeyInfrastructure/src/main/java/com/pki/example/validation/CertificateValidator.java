package com.pki.example.validation;

import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class CertificateValidator {

    public boolean isCAValid(X509Certificate caCert, X509Certificate parentOrNull) {
        try {
            System.out.println("=== VALIDATOR DEBUG ===");
            System.out.println("Certificate Subject: " + caCert.getSubjectDN());
            System.out.println("Certificate Issuer: " + caCert.getIssuerDN());
            
            // 1) Period važenja
            System.out.println("1. Proveravam period važenja...");
            caCert.checkValidity();
            System.out.println("   ✓ Period važenja OK");

            // 2) BasicConstraints mora biti CA
            System.out.println("2. Proveravam BasicConstraints...");
            int basicConstraints = caCert.getBasicConstraints();
            System.out.println("   BasicConstraints value: " + basicConstraints);
            boolean isCA = basicConstraints != -1; // -1 znači nije CA
            if (!isCA) {
                System.out.println("   ✗ BasicConstraints CA=false");
                return false;
            }
            System.out.println("   ✓ BasicConstraints OK");

            // 3) KeyUsage: mora imati keyCertSign (i poželjno cRLSign)
            System.out.println("3. Proveravam KeyUsage...");
            boolean[] ku = caCert.getKeyUsage();
            if (ku != null) {
                System.out.println("   KeyUsage array length: " + ku.length);
                System.out.println("   KeyUsage: " + java.util.Arrays.toString(ku));
                boolean keyCertSign = ku.length > 5 && ku[5];
                boolean cRLSign     = ku.length > 6 && ku[6];
                System.out.println("   keyCertSign (index 5): " + keyCertSign);
                System.out.println("   cRLSign (index 6): " + cRLSign);
                if (!keyCertSign) {
                    System.out.println("   ✗ KeyUsage nema keyCertSign");
                    return false;
                }
                if (!cRLSign) {
                    System.out.println("   ⚠ (preporuka) nema cRLSign");
                }
            } else {
                System.out.println("   ⚠ KeyUsage nije postavljen");
            }
            System.out.println("   ✓ KeyUsage OK");

            // 4) Potpis
            System.out.println("4. Proveravam potpis...");
            boolean isSelfSigned = caCert.getSubjectX500Principal().equals(caCert.getIssuerX500Principal());
            System.out.println("   Self-signed: " + isSelfSigned);
            
            if (parentOrNull != null && !isSelfSigned) {
                // nije self-signed -> verifikuj na parent
                System.out.println("   Verifikujem na parent certificate...");
                caCert.verify(parentOrNull.getPublicKey());
            } else {
                // self-signed (root) -> verifikuj na sopstveni public key
                System.out.println("   Verifikujem na sopstveni public key...");
                caCert.verify(caCert.getPublicKey());
            }
            System.out.println("   ✓ Potpis OK");

            System.out.println("=== VALIDATOR PASSED ===");
            return true;

        } catch (Exception e) {
            System.out.println("=== VALIDATOR FAILED ===");
            System.out.println("Validator: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
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
