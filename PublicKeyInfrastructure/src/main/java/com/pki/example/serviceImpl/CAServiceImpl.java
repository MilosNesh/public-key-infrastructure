package com.pki.example.serviceImpl;

import com.pki.example.certificates.CACertificateGenerator;
import com.pki.example.data.*;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.service.CAService;
import com.pki.example.validation.CertificateValidator;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

@Service
public class CAServiceImpl implements CAService {

    @Autowired
    private CACertificateGenerator caGenerator;

    @Autowired
    private KeyStoreWriter keyStoreWriter;

    @Autowired
    private KeyStoreReader keyStoreReader;

    @Autowired
    private CertificateValidator validator;


    @Override
    public CertificateResponse createRootCA(CARequest request) throws Exception {

        // 1. Generisanje ključeva
        KeyPair keyPair = generateKeyPair();

        // 2. Kreiranje X500Name za CA
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, request.getCommonName());
        builder.addRDN(BCStyle.O, request.getOrganization());
        builder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, request.getCountry());
        builder.addRDN(BCStyle.E, request.getEmail());

        // 3. Kreiranje Issuer objekta (Root CA potpisuje sam sebe)
        Issuer issuer = new Issuer(
                keyPair.getPrivate(),
                keyPair.getPublic(),
                builder.build()
        );

        // 4. Generisanje Root CA sertifikata
        X509Certificate rootCA = caGenerator.generateRootCACertificate(
                issuer,
                request.getStartDate(),
                request.getEndDate(),
                request.getSerialNumber()
        );

        // 5. Čuvanje u keystore
        String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase();
        keyStoreWriter.loadKeyStore(null, "password".toCharArray()); // novi keystore
        keyStoreWriter.write(alias, keyPair.getPrivate(), "password".toCharArray(), rootCA);
        keyStoreWriter.saveKeyStore("src/main/resources/static/ca-keystore.jks", "password".toCharArray());

        // 6. Response
        CertificateResponse response = new CertificateResponse();
        response.setAlias(alias);
        response.setSubjectDN(rootCA.getSubjectDN().toString());
        response.setIssuerDN(rootCA.getIssuerDN().toString());
        response.setSerialNumber(rootCA.getSerialNumber().toString());
        response.setNotBefore(rootCA.getNotBefore());
        response.setNotAfter(rootCA.getNotAfter());
        response.setCertificatePEM(Base64.getEncoder().encodeToString(rootCA.getEncoded()));
        response.setMessage("Root CA uspešno kreiran!");

        return response;
    }

    private KeyPair generateKeyPair() throws Exception {
        try{
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    @Override
    public CertificateResponse createIntermediateCA(IntermediateCARequest request) throws Exception{
        // 1. Učitavanje issuer CA-a iz keystore-a
        Issuer issuer = keyStoreReader.readIssuerFromStore(
                "src/main/resources/static/ca-keystore.jks",
                request.getIssuerAlias(),
                "password".toCharArray(),
                "password".toCharArray()
        );


        if (issuer == null) {
            throw new Exception("Issuer not found!");
        }

        // 2. Učitavanje issuer sertifikata
        X509Certificate issuerCert = (X509Certificate) keyStoreReader.readCertificate(
                "src/main/resources/static/ca-keystore.jks",
                "password",
                request.getIssuerAlias()
        );

        // 3. Validacija issuer CA-a
        if (!validator.isCAValid(issuerCert)) {
            throw new Exception("Issuer certificate not valid!");
        }

        // 4. Validacija perioda važenja
        if (!validator.canIssue(issuerCert, request.getStartDate(), request.getEndDate(), null)) {
            throw  new Exception("Period vazenja sertifikata nije validan");
        }

        // 5. Generisanje ključeva za novi CA
        KeyPair keyPair = generateKeyPair();

        // 6. Kreiranje X500Name za novi CA
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, request.getCommonName());
        builder.addRDN(BCStyle.O, request.getOrganization());
        builder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, request.getCountry());
        builder.addRDN(BCStyle.E, request.getEmail());

        Subject subject = new Subject(keyPair.getPublic(), builder.build());

        // 7. Generisanje Intermediate CA sertifikata
        X509Certificate intermediateCA = caGenerator.generateIntermediateCACertificate(
                subject,
                issuer,
                issuerCert,
                request.getStartDate(),
                request.getEndDate(),
                request.getSerialNumber(),
                request.getPathLength()
        );

        // 8. Čuvanje u keystore
        String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase();
        keyStoreWriter.loadKeyStore("src/main/resources/static/ca-keystore.jks", "password".toCharArray());
        keyStoreWriter.write(alias, keyPair.getPrivate(), "password".toCharArray(), intermediateCA);
        keyStoreWriter.saveKeyStore("src/main/resources/static/ca-keystore.jks", "password".toCharArray());

        // 9. Response
        CertificateResponse response = new CertificateResponse();
        response.setAlias(alias);
        response.setSubjectDN(intermediateCA.getSubjectDN().toString());
        response.setIssuerDN(intermediateCA.getIssuerDN().toString());
        response.setSerialNumber(intermediateCA.getSerialNumber().toString());
        response.setNotBefore(intermediateCA.getNotBefore());
        response.setNotAfter(intermediateCA.getNotAfter());
        response.setCertificatePEM(Base64.getEncoder().encodeToString(intermediateCA.getEncoded()));
        response.setMessage("Intermediate CA uspešno kreiran!");

        return response;
    }

    @Override
    public List<CertificateResponse> getAll() {
        List<CertificateResponse> out = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream("src/main/resources/static/ca-keystore.jks")) {

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(fis, "password".toCharArray());

            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                // U keystore-u sertifikat može biti deo key entry-ja ili samostalni cert entry
                if (!(ks.isKeyEntry(alias) || ks.isCertificateEntry(alias))) continue;

                var cert = ks.getCertificate(alias);
                if (!(cert instanceof X509Certificate)) continue;

                X509Certificate x = (X509Certificate) cert;

                CertificateResponse resp = new CertificateResponse();
                resp.setAlias(alias);
                resp.setSubjectDN(x.getSubjectDN().toString());
                resp.setIssuerDN(x.getIssuerDN().toString());
                resp.setSerialNumber(x.getSerialNumber().toString());
                resp.setNotBefore(x.getNotBefore());
                resp.setNotAfter(x.getNotAfter());
                resp.setCertificatePEM(Base64.getEncoder().encodeToString(x.getEncoded()));

                out.add(resp);
            }

            return out;

        } catch (Exception e) {
            throw new RuntimeException("Ne mogu da pročitam keystore ili sertifikate: " + e.getMessage(), e);
        }
    }
}




