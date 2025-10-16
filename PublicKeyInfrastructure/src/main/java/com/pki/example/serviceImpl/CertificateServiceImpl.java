package com.pki.example.serviceImpl;

import com.pki.example.certificates.CACertificateGenerator;
import com.pki.example.data.*;
import com.pki.example.domain.User;
import com.pki.example.domain.UserCertificate;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.repo.UserCertificateRepository;
import com.pki.example.repo.UserRepository;
import com.pki.example.service.CertificateService;
import com.pki.example.util.PasswordGenerator;
import com.pki.example.util.SerialNumberUtil;
import com.pki.example.validation.CertificateValidator;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CertificateServiceImpl implements CertificateService {

    @Autowired
    private CACertificateGenerator caCertificateGenerator;

    @Autowired
    private KeyStoreWriter keyStoreWriter;

    @Autowired
    private KeyStoreReader keyStoreReader;

    @Autowired
    private UserCertificateRepository userCertificateRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CertificateValidator validator;

    private static final String KEYSTORE_PATH = "src/main/resources/static/ca-keystore.jks";
    private static final String KEYSTORE_PASSWORD = "password";

    @Override
    public CertificateResponse createRootCA(CARequest request) throws Exception {
        
        // 1. Generisanje RSA ključeva
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

        BigInteger serial32 = SerialNumberUtil.generateSerial(32);
        // 4. Generisanje Root CA sertifikata
        X509Certificate rootCA = caCertificateGenerator.generateRootCACertificate(
                issuer,
                request.getStartDate(),
                request.getEndDate(),
                serial32.toString()
        );

        // 5. Generisanje random lozinke za keystore
        String keyStorePassword = PasswordGenerator.generatePassword(20);

        String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase();
        String keystoreName = alias;
        String keystorePath = "src/main/resources/static/" + keystoreName + ".jks";

        keyStoreWriter.loadKeyStore(null, keyStorePassword.toCharArray()); // novi keystore
        keyStoreWriter.write(alias, keyPair.getPrivate(), keyStorePassword.toCharArray(), rootCA);
        keyStoreWriter.saveKeyStore(keystorePath, keyStorePassword.toCharArray());


        // 8. Čuvanje lozinke za privatni ključ u bazi (za user-a sa ID=1)
        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));
        
        UserCertificate userCertificate = new UserCertificate(
            user,
            Long.parseLong(serial32.toString()),
            keyStorePassword,  // Plain text lozinka (TODO: šifrovati kasnije)
                "src/main/resources/static/ca-keystore.jks"
        );
        userCertificateRepository.save(userCertificate);

        // 9. Response
        CertificateResponse response = new CertificateResponse();
        response.setAlias(alias);
        response.setSubjectDN(rootCA.getSubjectDN().toString());
        response.setIssuerDN(rootCA.getIssuerDN().toString());
        response.setSerialNumber(rootCA.getSerialNumber().toString());
        response.setNotBefore(rootCA.getNotBefore());
        response.setNotAfter(rootCA.getNotAfter());
        response.setCertificatePEM(Base64.getEncoder().encodeToString(rootCA.getEncoded()));
        response.setMessage("Root CA uspešno kreiran! Keystore: " + "src/main/resources/static/ca-keystore.jks");

        return response;
    }

    private KeyPair generateKeyPair() throws Exception {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new Exception(e);
        }
    }

    @Override
    public CertificateResponse createIntermediateCA(IntermediateCARequest request) throws Exception {
        
        // 1. Učitavanje issuer CA-a iz keystore-a
        Issuer issuer = keyStoreReader.readIssuerFromStore(
                KEYSTORE_PATH,
                request.getIssuerAlias(),
                KEYSTORE_PASSWORD.toCharArray(),
                KEYSTORE_PASSWORD.toCharArray()
        );

        if (issuer == null) {
            throw new Exception("Issuer not found!");
        }

        // 2. Učitavanje issuer sertifikata
        X509Certificate issuerCert = (X509Certificate) keyStoreReader.readCertificate(
                KEYSTORE_PATH,
                KEYSTORE_PASSWORD,
                request.getIssuerAlias()
        );

        // 3. Validacija issuer CA-a
        if (!validator.isCAValid(issuerCert)) {
            throw new Exception("Issuer certificate not valid!");
        }

        // 4. Validacija perioda važenja
        if (!validator.canIssue(issuerCert, request.getStartDate(), request.getEndDate())) {
            throw new Exception("Period važenja sertifikata nije validan");
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
        X509Certificate intermediateCA = caCertificateGenerator.generateIntermediateCACertificate(
                subject,
                issuer,
                issuerCert,
                request.getStartDate(),
                request.getEndDate(),
                request.getSerialNumber(),
                request.getPathLength()
        );

        // 8. Generisanje random lozinke za privatni ključ
        String privateKeyPassword = PasswordGenerator.generatePassword(20);

        // 9. Čuvanje u keystore
        String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase();
        keyStoreWriter.loadKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD.toCharArray());
        keyStoreWriter.write(alias, keyPair.getPrivate(), privateKeyPassword.toCharArray(), intermediateCA);
        keyStoreWriter.saveKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD.toCharArray());

        // 10. Čuvanje lozinke za privatni ključ u bazi (za user-a sa ID=1)
        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));
        
        UserCertificate userCertificate = new UserCertificate(
            user,
            Long.parseLong(request.getSerialNumber()),
            privateKeyPassword,  // Plain text lozinka (TODO: šifrovati kasnije)
            KEYSTORE_PATH
        );
        userCertificateRepository.save(userCertificate);

        // 11. Response
        CertificateResponse response = new CertificateResponse();
        response.setAlias(alias);
        response.setSubjectDN(intermediateCA.getSubjectDN().toString());
        response.setIssuerDN(intermediateCA.getIssuerDN().toString());
        response.setSerialNumber(intermediateCA.getSerialNumber().toString());
        response.setNotBefore(intermediateCA.getNotBefore());
        response.setNotAfter(intermediateCA.getNotAfter());
        response.setCertificatePEM(Base64.getEncoder().encodeToString(intermediateCA.getEncoded()));
        response.setMessage("Intermediate CA uspešno kreiran i lozinka sačuvana u bazi!");

        return response;
    }

    @Override
    public List<CertificateResponse> getAll() {
        List<CertificateResponse> out = new ArrayList<>();
        
        // Dobijamo sve keystore putanje iz baze
        List<UserCertificate> userCertificates = userCertificateRepository.findAll();
        List<String> keystorePaths = userCertificates.stream()
                .map(UserCertificate::getKeystorePath)
                .distinct()
                .collect(Collectors.toList());

        // Čitamo sertifikate iz svih keystore fajlova
        for (String keystorePath : keystorePaths) {
            try (FileInputStream fis = new FileInputStream(keystorePath)) {

                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(fis, KEYSTORE_PASSWORD.toCharArray());

                Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();

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

            } catch (Exception e) {
                // Logujemo grešku ali nastavljamo sa ostalim keystore-ovima
                System.err.println("Greška pri čitanju keystore-a " + keystorePath + ": " + e.getMessage());
            }
        }

        return out;
    }
}

