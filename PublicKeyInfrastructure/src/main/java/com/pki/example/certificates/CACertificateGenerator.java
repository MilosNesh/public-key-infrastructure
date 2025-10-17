package com.pki.example.certificates;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.validation.CertificateValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

@Component
public class CACertificateGenerator {

    @Autowired
    private CertificateValidator validator;

    public CACertificateGenerator() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public X509Certificate generateRootCACertificate(Issuer caData, Date startDate, Date endDate, String serialNumber) {
        try {
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            builder = builder.setProvider("BC");
            ContentSigner contentSigner = builder.build(caData.getPrivateKey());

            //Root CA, self-signed - issuer = subject
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                    caData.getX500Name(),           // issuer (CA potpisuje sam sebe)
                    new BigInteger(serialNumber),
                    startDate,
                    endDate,
                    caData.getX500Name(),           // subject (isti kao issuer - self-signed!)
                    caData.getPublicKey()
            );

            certGen.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(true));

            certGen.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier subjectKeyId = extUtils.createSubjectKeyIdentifier(caData.getPublicKey());
            certGen.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId);

            AuthorityKeyIdentifier authorityKeyId = extUtils.createAuthorityKeyIdentifier(caData.getPublicKey());
            certGen.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId);

            X509CertificateHolder certHolder = certGen.build(contentSigner);
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");

            return certConverter.getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Greška pri generisanju Root CA sertifikata", e);
        }
    }


    public X509Certificate generateIntermediateCACertificate(
            Subject subject,
            Issuer issuer,
            X509Certificate issuerCert,
            Date startDate,
            Date endDate,
            String serialNumber,
            Integer pathLength) {

        try {
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            builder = builder.setProvider("BC");
            ContentSigner contentSigner = builder.build(issuer.getPrivateKey());

            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                    issuer.getX500Name(),            // issuer (roditelj CA)
                    new BigInteger(serialNumber),
                    startDate,
                    endDate,
                    subject.getX500Name(),           // subject (novi CA)
                    subject.getPublicKey()           // javni ključ novog CA-a
            );

            BasicConstraints basicConstraints = (pathLength != null)
                    ? new BasicConstraints(pathLength)
                    : new BasicConstraints(true);
            certGen.addExtension(Extension.basicConstraints, true, basicConstraints);

            certGen.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier subjectKeyId = extUtils.createSubjectKeyIdentifier(subject.getPublicKey());
            certGen.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId);

            AuthorityKeyIdentifier authorityKeyId = extUtils.createAuthorityKeyIdentifier(issuerCert);
            certGen.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId);

            X509CertificateHolder certHolder = certGen.build(contentSigner);
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");

            return certConverter.getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Greška pri generisanju Intermediate CA sertifikata", e);
        }
    }
}