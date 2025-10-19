package com.pki.example.serviceImpl;

import com.pki.example.certificates.CACertificateGenerator;
import com.pki.example.data.*;
import com.pki.example.domain.UserCertificate;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.repo.UserCertificateRepository;
import com.pki.example.repository.UserRepository;
import com.pki.example.service.CertificateService;
import com.pki.example.util.CertificateUtils;
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
        User user = userRepository.findById(1)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));
        
        UserCertificate userCertificate = new UserCertificate(
            user,
            Long.parseLong(serial32.toString()),
            keyStorePassword,  // Plain text lozinka (TODO: šifrovati kasnije)
                keystorePath
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
        response.setMessage("Root CA uspešno kreiran! Keystore: " + "src/main/resources/static/" + keystorePath + ".jks");

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
    public CertificateResponse createIntermediateCA(IntermediateCARequest request, Integer issuerUserId) throws Exception {

        List<UserCertificate> userCertificates = userCertificateRepository.findByUserId(issuerUserId);

        if (userCertificates.size() == 0) {
            throw new Exception("Issuer not found!");
        }

        String aliasToFind = request.getIssuerAlias();
        UserCertificate matchingCertificate = null;

        for (UserCertificate uc : userCertificates) {
            try (FileInputStream fis = new FileInputStream(uc.getKeystorePath())) {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(fis, uc.getKeystorePassword().toCharArray());

                if (ks.containsAlias(aliasToFind)) {
                    matchingCertificate = uc;
                    break; // našli smo sertifikat, možemo da prekinemo
                }

            } catch (Exception e) {
                System.err.println("Greška pri čitanju keystore-a " + uc.getKeystorePath() + ": " + e.getMessage());
            }
        }

        // 2. Učitavanje issuer sertifikata
        X509Certificate issuerCert = (X509Certificate) keyStoreReader.readCertificate(
                matchingCertificate.getKeystorePath(),
                matchingCertificate.getKeystorePassword(),
                request.getIssuerAlias()
        );

        Issuer issuer = keyStoreReader.readIssuerFromStore(
                matchingCertificate.getKeystorePath(),
                request.getIssuerAlias(),
                matchingCertificate.getKeystorePassword().toCharArray(),
                matchingCertificate.getKeystorePassword().toCharArray()
        );


        if (matchingCertificate == null) {
            throw new Exception("Sertifikat sa aliasom '" + aliasToFind + "' nije pronađen ni u jednom keystore-u korisnika!");
        }

        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(matchingCertificate.getKeystorePath())) {
            ks.load(fis, matchingCertificate.getKeystorePassword().toCharArray());
        }
        java.security.cert.Certificate[] issuerChain = ks.getCertificateChain(request.getIssuerAlias());

        X509Certificate parentOrNull = null;
        if (issuerChain != null && issuerChain.length >= 2) {
            parentOrNull = (X509Certificate) issuerChain[1]; // roditelj iznad issuer-a
        } else {
            // ako je issuer root (self-signed), parent može ostati null
            parentOrNull = null;
        }

        // PROVERA VALIDNOSTI: (umesto stare varijante)
        if (!validator.isCAValid(issuerCert, parentOrNull)) {
            throw new Exception("Issuer certificate not valid!");
        }

        // PROVERA PERIODA:
        if (!validator.canIssue(issuerCert, request.getStartDate(), request.getEndDate(), parentOrNull)) {
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
        BigInteger serial32 = SerialNumberUtil.generateSerial(32);

        // 7. Generisanje Intermediate CA sertifikata
        X509Certificate intermediateCA = caCertificateGenerator.generateIntermediateCACertificate(
                subject,
                issuer,
                issuerCert,
                request.getStartDate(),
                request.getEndDate(),
                serial32.toString(),
                request.getPathLength()
        );

        // 8. Generisanje random lozinke za privatni ključ
        String privateKeyPassword = PasswordGenerator.generatePassword(20);

        String keystorePathToUse = matchingCertificate.getKeystorePath();
        String keyStorePassword = matchingCertificate.getKeystorePassword();

        boolean issuerHasChildren = CertificateUtils.issuerHasChildren(
                issuerCert,
                matchingCertificate.getKeystorePath(),
                matchingCertificate.getKeystorePassword().toCharArray()
        );


        if (issuerHasChildren) {
            // Novi keystore jer dolazi do grananja
            keyStorePassword = PasswordGenerator.generatePassword(20);

            String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase();
            keystorePathToUse = "src/main/resources/static/" + alias + ".jks";
            keyStoreWriter.loadKeyStore(null, keyStorePassword.toCharArray());

            keyStoreWriter.saveKeyStore(keystorePathToUse, keyStorePassword.toCharArray());
        } else {
            // Nastavi u isti keystore
            keyStoreWriter.loadKeyStore(keystorePathToUse, keyStorePassword.toCharArray());
        }

        String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase();
        List<X509Certificate> chainList = buildCertificateChain(
                matchingCertificate.getKeystorePath(),
                matchingCertificate.getKeystorePassword(),
                request.getIssuerAlias()
        );
        chainList.add(0, intermediateCA);
        X509Certificate[] chain = chainList.toArray(new X509Certificate[0]);

        keyStoreWriter.writeChain(alias, keyPair.getPrivate(), keyStorePassword.toCharArray(), chain);
        keyStoreWriter.saveKeyStore(keystorePathToUse, keyStorePassword.toCharArray());

        // 10. Čuvanje lozinke za privatni ključ u bazi (za user-a sa ID=1)
        User user = userRepository.findById(1)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));
        UserCertificate userCertificate = new UserCertificate(
                user,
                Long.parseLong(serial32.toString()),
                keyStorePassword,
                keystorePathToUse
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

    private List<X509Certificate> buildCertificateChain(String keystorePath, String password, String alias) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();

        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password.toCharArray());
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (cert == null) {
            throw new Exception("Sertifikat sa aliasom " + alias + " nije pronađen u keystore-u " + keystorePath);
        }

        System.out.println("Sertifikat u lancu: " + cert.getIssuerDN());
        chain.add(cert);

        // Ako issuer != subject → pokušaj da nađeš roditelja u istom keystore-u
        String issuerDN = cert.getIssuerX500Principal().getName();
        String subjectDN = cert.getSubjectX500Principal().getName();

        if (!issuerDN.equals(subjectDN)) {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                X509Certificate potentialParent = (X509Certificate) ks.getCertificate(a);
                if (potentialParent.getSubjectX500Principal().getName().equals(issuerDN)) {
                    // Rekurzivno dodaj ostatak lanca
                    chain.addAll(buildCertificateChain(keystorePath, password, a));
                    break;
                }
            }
        }

        return chain;
    }

}

