package com.pki.example.certificates;

import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import com.pki.example.data.ExtendedRequest;
import com.pki.example.validation.CertificateValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
public class CACertificateGenerator {

    @Autowired
    private CertificateValidator validator;

    public CACertificateGenerator() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public X509Certificate generateRootCACertificate(Issuer caData, Date startDate, Date endDate, String serialNumber) {
        // Pozovi novu metodu sa default vrednostima
        return generateRootCACertificate(caData, startDate, endDate, serialNumber, null, null, null, null, null);
    }

    public X509Certificate generateRootCACertificate(Issuer caData, Date startDate, Date endDate, String serialNumber,
                                                     Integer pathLength, List<String> keyUsages, List<String> extendedKeyUsages,
                                                     List<String> sanList, List<ExtendedRequest.AdditionalExtension> additionalExtensions) {
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

            // Basic Constraints - koristi pathLength ako je prosleđen, inače true (unlimited)
            boolean isCA = true;
            if (pathLength != null) {
                certGen.addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(pathLength));
            } else {
                certGen.addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(true));
            }

            // Key Usage - koristi custom keyUsages ako su prosleđeni
            if (keyUsages != null && !keyUsages.isEmpty()) {
                int keyUsageFlags = 0;
                for (String usage : keyUsages) {
                    switch (usage.toLowerCase()) {
                        case "digital_signature":
                        case "digitalsignature":
                            keyUsageFlags |= KeyUsage.digitalSignature;
                            break;
                        case "key_cert_sign":
                        case "keycertsign":
                        case "cert_sign":
                        case "certsign":
                            keyUsageFlags |= KeyUsage.keyCertSign;
                            break;
                        case "crl_sign":
                        case "crlsign":
                            keyUsageFlags |= KeyUsage.cRLSign;
                            break;
                        case "key_encipherment":
                        case "keyencipherment":
                            keyUsageFlags |= KeyUsage.keyEncipherment;
                            break;
                        case "data_encipherment":
                        case "dataencipherment":
                            keyUsageFlags |= KeyUsage.dataEncipherment;
                            break;
                        case "key_agreement":
                        case "keyagreement":
                            keyUsageFlags |= KeyUsage.keyAgreement;
                            break;
                        case "non_repudiation":
                        case "nonrepudiation":
                            keyUsageFlags |= KeyUsage.nonRepudiation;
                            break;
                        case "encipher_only":
                        case "encipheronly":
                            keyUsageFlags |= KeyUsage.encipherOnly;
                            break;
                        case "decipher_only":
                        case "decipheronly":
                            keyUsageFlags |= KeyUsage.decipherOnly;
                            break;
                        default:
                            System.err.println("Nepoznato KeyUsage: " + usage);
                    }
                }
                System.out.println("Root CA - Kreiram KeyUsage sa flags: " + keyUsageFlags + " za usage-e: " + keyUsages);
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageFlags));
            } else {
                // Default za Root CA
                certGen.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            }

            // Extended Key Usage - dodaj ako su prosleđeni
            if (extendedKeyUsages != null && !extendedKeyUsages.isEmpty()) {
                // Implementiraj po potrebi
            }

            // Subject Alternative Name - dodaj ako su prosleđeni
            if (sanList != null && !sanList.isEmpty()) {
                List<GeneralName> names = new ArrayList<>();
                for (String san : sanList) {
                    if (san.contains("@")) {
                        names.add(new GeneralName(GeneralName.rfc822Name, san));
                    } else {
                        names.add(new GeneralName(GeneralName.dNSName, san));
                    }
                }
                GeneralName[] nameArray = names.toArray(new GeneralName[0]);
                GeneralNames generalNames = new GeneralNames(nameArray);

                certGen.addExtension(Extension.subjectAlternativeName, false, generalNames);
            }

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier subjectKeyId = extUtils.createSubjectKeyIdentifier(caData.getPublicKey());
            certGen.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId);

            AuthorityKeyIdentifier authorityKeyId = extUtils.createAuthorityKeyIdentifier(caData.getPublicKey());
            certGen.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId);

            // Additional Extensions - dodaj ako su prosleđeni
            if (additionalExtensions != null && !additionalExtensions.isEmpty()) {
                for (ExtendedRequest.AdditionalExtension ext : additionalExtensions) {
                    // Implementiraj dodavanje dodatnih ekstenzija po potrebi
                    // Ovo je placeholder - trebalo bi da implementiraš specifičnu logiku za svaki tip ekstenzije
                }
            }

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
        // Pozovi novu metodu sa default vrednostima
        return generateIntermediateCACertificate(subject, issuer, issuerCert, startDate, endDate, serialNumber, 
                                               pathLength, null, null, null, null);
    }

    public X509Certificate generateIntermediateCACertificate(
            Subject subject,
            Issuer issuer,
            X509Certificate issuerCert,
            Date startDate,
            Date endDate,
            String serialNumber,
            Integer pathLength,
            List<String> keyUsages,
            List<String> extendedKeyUsages,
            List<String> sanList,
            List<ExtendedRequest.AdditionalExtension> additionalExtensions) {

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

            // Key Usage - koristi custom keyUsages ako su prosleđeni
            if (keyUsages != null && !keyUsages.isEmpty()) {
                int keyUsageFlags = 0;
                for (String usage : keyUsages) {
                    switch (usage.toLowerCase()) {
                        case "digital_signature":
                        case "digitalsignature":
                            keyUsageFlags |= KeyUsage.digitalSignature;
                            break;
                        case "key_cert_sign":
                        case "keycertsign":
                        case "cert_sign":
                        case "certsign":
                            keyUsageFlags |= KeyUsage.keyCertSign;
                            break;
                        case "crl_sign":
                        case "crlsign":
                            keyUsageFlags |= KeyUsage.cRLSign;
                            break;
                        case "key_encipherment":
                        case "keyencipherment":
                            keyUsageFlags |= KeyUsage.keyEncipherment;
                            break;
                        case "data_encipherment":
                        case "dataencipherment":
                            keyUsageFlags |= KeyUsage.dataEncipherment;
                            break;
                        case "key_agreement":
                        case "keyagreement":
                            keyUsageFlags |= KeyUsage.keyAgreement;
                            break;
                        case "non_repudiation":
                        case "nonrepudiation":
                            keyUsageFlags |= KeyUsage.nonRepudiation;
                            break;
                        case "encipher_only":
                        case "encipheronly":
                            keyUsageFlags |= KeyUsage.encipherOnly;
                            break;
                        case "decipher_only":
                        case "decipheronly":
                            keyUsageFlags |= KeyUsage.decipherOnly;
                            break;
                        default:
                            System.err.println("Nepoznato KeyUsage: " + usage);
                    }
                }
                System.out.println("Kreiram KeyUsage sa flags: " + keyUsageFlags + " za usage-e: " + keyUsages);
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageFlags));
            } else {
                // Default za Intermediate CA
                certGen.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            }

            // Subject Alternative Name - dodaj ako su prosleđeni
            if (sanList != null && !sanList.isEmpty()) {
                List<GeneralName> names = new ArrayList<>();
                for (String san : sanList) {
                    if (san.contains("@")) {
                        names.add(new GeneralName(GeneralName.rfc822Name, san));
                    } else {
                        names.add(new GeneralName(GeneralName.dNSName, san));
                    }
                }
                GeneralName[] nameArray = names.toArray(new GeneralName[0]);
                GeneralNames generalNames = new GeneralNames(nameArray);
                certGen.addExtension(Extension.subjectAlternativeName, false, generalNames);
            }

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

    public X509Certificate generateEndEntityCertificate(
            Subject subject,
            Issuer issuer,
            X509Certificate issuerCert,
            Date startDate,
            Date endDate,
            String serialNumber
    ) {
        try {
            // 1. Priprema Content Signera – CA privatni ključ
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            builder.setProvider("BC");
            ContentSigner contentSigner = builder.build(issuer.getPrivateKey());

            // 2. Kreiranje X509v3CertificateBuilder-a
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                    issuer.getX500Name(),          // issuer = CA
                    new BigInteger(serialNumber),
                    startDate,
                    endDate,
                    subject.getX500Name(),         // subject = end-entity
                    subject.getPublicKey()         // javni ključ end-entity-ja
            );

            // 3. Basic constraints: false (nije CA)
            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

            // 4. KeyUsage – zavisno od toga čemu sertifikat služi
            certGen.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            // 6. Subject i Authority key identifiers
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            SubjectKeyIdentifier subjectKeyId = extUtils.createSubjectKeyIdentifier(subject.getPublicKey());
            certGen.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId);

            AuthorityKeyIdentifier authorityKeyId = extUtils.createAuthorityKeyIdentifier(issuerCert);
            certGen.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId);

            // 7. Generisanje i konverzija u X509Certificate
            X509CertificateHolder certHolder = certGen.build(contentSigner);
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");

            return certConverter.getCertificate(certHolder);

        } catch (OperatorCreationException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Greška pri generisanju end-entity sertifikata", e);
        }
    }


    public X509Certificate generateEndEntityCertificateFromCsr(
            PKCS10CertificationRequest csr,
            Issuer issuer,
            X509Certificate issuerCert,
            Date startDate,
            Date endDate,
            String serialNumber
    ) {
        try {
            // 1) Izvuci subject i public key iz CSR-a
            X500Name subjectName = csr.getSubject();
            SubjectPublicKeyInfo spki = csr.getSubjectPublicKeyInfo();
            PublicKey subjectPublicKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(spki);

            // 2) Napravi Subject domen objekat
            Subject subject = new Subject(subjectPublicKey, subjectName);

            // 3) Delegiraj na postojeću metodu
            return generateEndEntityCertificate(subject, issuer, issuerCert, startDate, endDate, serialNumber);
        } catch (Exception e) {
            throw new RuntimeException("Neuspešna obrada CSR-a", e);
        }
    }
}