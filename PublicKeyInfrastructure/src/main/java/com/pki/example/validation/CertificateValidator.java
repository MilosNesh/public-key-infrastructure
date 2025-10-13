package com.pki.example.validation;

import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class CertificateValidator {

    public boolean isCAValid(X509Certificate issuerCert) {
        if (!isWithinValidityPeriod(issuerCert)) {
            System.out.println("CA sertifikat je istekao ili još nije validan!");
            return false;
        }

        if (!isSignatureValid(issuerCert, issuerCert)) {
            System.out.println("CA sertifikat ima neispravan potpis!");
            return false;
        }

        // Provera da li je sertifikat povucen

        return true;
    }

    public boolean isWithinValidityPeriod(X509Certificate certificate) {
        try {
            Date now = new Date();
            Date notBefore = certificate.getNotBefore();
            Date notAfter = certificate.getNotAfter();

            if (now.before(notBefore)) {
                System.out.println("Sertifikat još nije aktivan. Aktivan od: " + notBefore);
                return false;
            }

            if (now.after(notAfter)) {
                System.out.println("Sertifikat je istekao. Istekao: " + notAfter);
                return false;
            }

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean isSignatureValid(X509Certificate certificate, X509Certificate issuerCertificate) {
        try {
            PublicKey issuerPublicKey = issuerCertificate.getPublicKey();
            certificate.verify(issuerPublicKey);
            return true;
        } catch (Exception e) {
            System.out.println("Greška pri proveri potpisa: " + e.getMessage());
            return false;
        }
    }

    public boolean canIssue(X509Certificate issuerCert, Date startDate, Date endDate) {

        if (!isCAValid(issuerCert)) {
            return false;
        }

        // novi sertifikat ne sme da važi duže od CA-a
        if (endDate.after(issuerCert.getNotAfter())) {
            System.out.println("Novi sertifikat ne može da važi duže od CA-a!");
            System.out.println("CA ističe: " + issuerCert.getNotAfter());
            System.out.println("Traženo: " + endDate);
            return false;
        }

        // početak novog sertifikata mora biti posle početka CA-a
        if (startDate.before(issuerCert.getNotBefore())) {
            System.out.println("Novi sertifikat ne može da počne pre CA-a!");
            return false;
        }

        return true;
    }
}
