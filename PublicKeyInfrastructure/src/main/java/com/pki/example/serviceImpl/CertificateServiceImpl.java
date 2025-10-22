package com.pki.example.serviceImpl;

import com.pki.example.certificates.CACertificateGenerator;
import com.pki.example.data.*;
import com.pki.example.domain.UserCertificate;
import com.pki.example.dto.CAWithValidityDTO;
import com.pki.example.dto.ExtendedCAResponseDTO;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.repository.UserCertificateRepository;
import com.pki.example.repository.UserRepository;
import com.pki.example.service.CertificateService;
import com.pki.example.service.KekService;
import com.pki.example.util.CertificateUtils;
import com.pki.example.util.PasswordGenerator;
import com.pki.example.util.SerialNumberUtil;
import com.pki.example.validation.CertificateValidator;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.time.ZoneId;
import java.util.*;
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

    @Autowired
    private KekService kekService;

    @Autowired
    private AesGcmService aesGcmService;

    private String aliasFromKeystorePath(String keystorePath) {
        if (keystorePath == null) return null;
        String fileName = Paths.get(keystorePath).getFileName().toString();
        int dot = fileName.lastIndexOf('.');
        return dot > 0 ? fileName.substring(0, dot) : fileName;
    }

    private boolean isKeystorePath(String p) {
        if (p == null) return false;
        String s = p.toLowerCase(Locale.ROOT);
        return s.endsWith(".jks") || s.endsWith(".p12") || s.endsWith(".pfx");
    }

    private boolean isDerPath(String p) {
        if (p == null) return false;
        String s = p.toLowerCase(Locale.ROOT);
        return s.endsWith(".der") || s.endsWith(".cer") || s.endsWith(".crt");
    }

    private KeyStore newKeyStoreForPath(String p) throws KeyStoreException {
        String s = p.toLowerCase(Locale.ROOT);
        if (s.endsWith(".p12") || s.endsWith(".pfx")) return KeyStore.getInstance("PKCS12");
        return KeyStore.getInstance("JKS");
    }

    public char[] decryptKeystorePasswordIfNeeded(String keystorePath, String tokenOrPlain) throws Exception {
        if (tokenOrPlain == null) return null;
        if (!tokenOrPlain.startsWith("v1:")) {
            return tokenOrPlain.toCharArray();
        }
        String[] parts = tokenOrPlain.split(":");
        if (parts.length != 3) {
            throw new IllegalStateException("Invalid v1 token format for keystore password.");
        }
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] ct = Base64.getDecoder().decode(parts[2]);

        SecretKey kek = kekService.getOrCreateKek(1L);
        byte[] aad = ("keystore:" + aliasFromKeystorePath(keystorePath)).getBytes(StandardCharsets.UTF_8);

        byte[] pt = aesGcmService.decryptBytesWithKey(kek, iv, ct, aad);
        char[] pwd = new String(pt, StandardCharsets.UTF_8).toCharArray();
        java.util.Arrays.fill(pt, (byte) 0);
        return pwd;
    }

    @Override
    public ExtendedCAResponseDTO createRootCA(ExtendedRequest request) throws Exception {

        System.out.println("Issuerrrr: " + request.getIssuerAlias());

        if (request.getIsCA() != null && !request.getIsCA()) {
            System.out.println("Kreiranje End Entity sertifikata (isCA = false)");
            return createEndEntityCertificate(request);
        }

        if (request.getIssuerAlias() != null && !request.getIssuerAlias().trim().isEmpty()) {
            return createIntermediateCAFromExtendedRequest(request);
        }

        KeyPair keyPair = generateKeyPair();

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, request.getCommonName());
        builder.addRDN(BCStyle.O, request.getOrganization());
        builder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, request.getCountry());
        builder.addRDN(BCStyle.E, request.getEmail());

        Issuer issuer = new Issuer(
                keyPair.getPrivate(),
                keyPair.getPublic(),
                builder.build()
        );

        Date startDate = request.getStartDate() != null
                ? Date.from(request.getStartDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
                : new Date();
        Date endDate = request.getEndDate() != null
                ? Date.from(request.getEndDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
                : new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));

        String serialNumber = (request.getSerialNumber() != null && !request.getSerialNumber().trim().isEmpty())
                ? request.getSerialNumber()
                : SerialNumberUtil.generateSerial(32).toString();

        X509Certificate rootCA = caCertificateGenerator.generateRootCACertificate(
                issuer,
                startDate,
                endDate,
                serialNumber,
                request.getPathLength(),
                request.getKeyUsages(),
                request.getExtendedKeyUsages(),
                request.getSanList(),
                request.getAdditionalExtensions()
        );

        String keyStorePassword = PasswordGenerator.generatePassword(20);

        String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase(Locale.ROOT);
        String keystoreName = alias;
        String keystorePath = "src/main/resources/static/" + keystoreName + ".jks";

        keyStoreWriter.loadKeyStore(null, keyStorePassword.toCharArray());
        keyStoreWriter.write(alias, keyPair.getPrivate(), keyStorePassword.toCharArray(), rootCA);
        keyStoreWriter.saveKeyStore(keystorePath, keyStorePassword.toCharArray());

        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));

        SecretKey kek = kekService.getOrCreateKek(user.getId());
        byte[] aad = ("keystore:" + aliasFromKeystorePath(keystorePath)).getBytes(StandardCharsets.UTF_8);

        AesGcmService.EncBlob blob = aesGcmService.encryptBytesWithKey(
                kek,
                keyStorePassword.getBytes(StandardCharsets.UTF_8),
                aad
        );
        String encToken = "v1:" +
                Base64.getEncoder().encodeToString(blob.getIv()) + ":" +
                Base64.getEncoder().encodeToString(blob.getCt());

        UserCertificate userCertificate = new UserCertificate(
                user,
                Long.parseLong(serialNumber),
                encToken,
                keystorePath
        );
        userCertificateRepository.save(userCertificate);

        ExtendedCAResponseDTO response = createExtendedCAResponseDTO(rootCA, alias, request, null);
        response.setMessage("Root CA uspešno kreiran! Keystore: " + keystorePath);
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
    public ExtendedCAResponseDTO createIntermediateCA(ExtendedRequest request, Long issuerUserId) throws Exception {

        List<UserCertificate> userCertificates = userCertificateRepository.findByUserId(issuerUserId);
        if (userCertificates.isEmpty()) {
            throw new Exception("Issuer not found!");
        }

        String aliasToFind = request.getIssuerAlias();
        UserCertificate matchingCertificate = null;

        for (UserCertificate uc : userCertificates) {
            String path = uc.getKeystorePath();
            if (!isKeystorePath(path)) continue; // preskoči DER/CRT kao potencijalne issuere

            try (FileInputStream fis = new FileInputStream(path)) {
                KeyStore ks = newKeyStoreForPath(path);

                char[] decryptedPassword = decryptKeystorePasswordIfNeeded(path, uc.getKeystorePassword());
                ks.load(fis, decryptedPassword);
                java.util.Arrays.fill(decryptedPassword, '\0');

                if (ks.containsAlias(aliasToFind)) {
                    matchingCertificate = uc;
                    break;
                }

            } catch (Exception e) {
                System.err.println("Greška pri čitanju keystore-a " + path + ": " + e.getMessage());
            }
        }

        if (matchingCertificate == null) {
            throw new Exception("Sertifikat sa aliasom '" + aliasToFind + "' nije pronađen ni u jednom keystore-u korisnika!");
        }

        // 2. Učitavanje issuer sertifikata
        char[] matchingPwd = decryptKeystorePasswordIfNeeded(
                matchingCertificate.getKeystorePath(),
                matchingCertificate.getKeystorePassword()
        );
        String matchingPwdStr = matchingPwd == null ? null : new String(matchingPwd);

        X509Certificate issuerCert = (X509Certificate) keyStoreReader.readCertificate(
                matchingCertificate.getKeystorePath(),
                matchingPwdStr,
                request.getIssuerAlias()
        );

        Issuer issuer = keyStoreReader.readIssuerFromStore(
                matchingCertificate.getKeystorePath(),
                request.getIssuerAlias(),
                matchingPwdStr != null ? matchingPwdStr.toCharArray() : null,
                matchingPwdStr != null ? matchingPwdStr.toCharArray() : null
        );

        if (matchingPwd != null) java.util.Arrays.fill(matchingPwd, '\0');

        KeyStore ks = newKeyStoreForPath(matchingCertificate.getKeystorePath());
        try (FileInputStream fis = new FileInputStream(matchingCertificate.getKeystorePath())) {
            ks.load(fis, matchingPwdStr != null ? matchingPwdStr.toCharArray() : null);
        }
        java.security.cert.Certificate[] issuerChain = ks.getCertificateChain(request.getIssuerAlias());

        X509Certificate parentOrNull = null;
        if (issuerChain != null && issuerChain.length >= 2) {
            parentOrNull = (X509Certificate) issuerChain[1];
        }

        System.out.println("Proveravam issuer sertifikat: ");
        System.out.println("  Subject: " + issuerCert.getSubjectDN());
        System.out.println("  Issuer: " + issuerCert.getIssuerDN());
        System.out.println("  Serial: " + issuerCert.getSerialNumber());
        System.out.println("  BasicConstraints: " + issuerCert.getBasicConstraints());
        System.out.println("  KeyUsage: " + java.util.Arrays.toString(issuerCert.getKeyUsage()));

        if (!validator.isCAValid(issuerCert, parentOrNull)) {
            throw new Exception("Issuer certificate not valid! Proverite BasicConstraints, KeyUsage ili period važenja.");
        }

        Date startDate = request.getStartDate() != null
                ? Date.from(request.getStartDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
                : new Date();
        Date endDate = request.getEndDate() != null
                ? Date.from(request.getEndDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
                : new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));

        if (!validator.canIssue(issuerCert, startDate, endDate, parentOrNull)) {
            throw new Exception("Period važenja sertifikata nije validan");
        }

        KeyPair keyPair = generateKeyPair();

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, request.getCommonName());
        builder.addRDN(BCStyle.O, request.getOrganization());
        builder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, request.getCountry());
        builder.addRDN(BCStyle.E, request.getEmail());

        Subject subject = new Subject(keyPair.getPublic(), builder.build());

        String serialNumber = (request.getSerialNumber() != null && !request.getSerialNumber().trim().isEmpty())
                ? request.getSerialNumber()
                : SerialNumberUtil.generateSerial(32).toString();

        X509Certificate intermediateCA = caCertificateGenerator.generateIntermediateCACertificate(
                subject,
                issuer,
                issuerCert,
                startDate,
                endDate,
                serialNumber,
                request.getPathLength(),
                request.getKeyUsages(),
                request.getExtendedKeyUsages(),
                request.getSanList(),
                request.getAdditionalExtensions()
        );

        String keystorePathToUse = matchingCertificate.getKeystorePath();
        String keyStorePassword = matchingPwdStr;

        boolean issuerHasChildren = CertificateUtils.issuerHasChildren(
                issuerCert,
                matchingCertificate.getKeystorePath(),
                matchingPwdStr != null ? matchingPwdStr.toCharArray() : null
        );

        if (issuerHasChildren) {
            keyStorePassword = PasswordGenerator.generatePassword(20);
            String newAlias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase(Locale.ROOT);
            keystorePathToUse = "src/main/resources/static/" + newAlias + ".jks";
            keyStoreWriter.loadKeyStore(null, keyStorePassword.toCharArray());
            keyStoreWriter.saveKeyStore(keystorePathToUse, keyStorePassword.toCharArray());
        } else {
            keyStoreWriter.loadKeyStore(keystorePathToUse, keyStorePassword != null ? keyStorePassword.toCharArray() : null);
        }

        String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase(Locale.ROOT);
        List<X509Certificate> chainList = buildCertificateChain(
                matchingCertificate.getKeystorePath(),
                matchingPwdStr != null ? matchingPwdStr : "",
                request.getIssuerAlias()
        );
        chainList.add(0, intermediateCA);
        X509Certificate[] chain = chainList.toArray(new X509Certificate[0]);

        keyStoreWriter.writeChain(alias, keyPair.getPrivate(), keyStorePassword.toCharArray(), chain);
        keyStoreWriter.saveKeyStore(keystorePathToUse, keyStorePassword.toCharArray());

        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));

        SecretKey kek = kekService.getOrCreateKek(user.getId());
        byte[] aad2 = ("keystore:" + aliasFromKeystorePath(keystorePathToUse)).getBytes(StandardCharsets.UTF_8);

        AesGcmService.EncBlob blob = aesGcmService.encryptBytesWithKey(
                kek,
                keyStorePassword.getBytes(StandardCharsets.UTF_8),
                aad2
        );
        String encToken = "v1:" +
                Base64.getEncoder().encodeToString(blob.getIv()) + ":" +
                Base64.getEncoder().encodeToString(blob.getCt());

        UserCertificate userCertificate = new UserCertificate(
                user,
                Long.parseLong(serialNumber),
                encToken,
                keystorePathToUse
        );
        userCertificateRepository.save(userCertificate);

        ExtendedCAResponseDTO response = createExtendedCAResponseDTO(intermediateCA, alias, request, request.getIssuerAlias());
        response.setMessage("Intermediate CA uspešno kreiran i lozinka sačuvana u bazi!");
        return response;
    }

    private List<X509Certificate> buildCertificateChain(String keystorePath, String password, String alias) throws Exception {
        if (!isKeystorePath(keystorePath)) {
            throw new Exception("buildCertificateChain: prosleđen nije keystore fajl: " + keystorePath);
        }

        List<X509Certificate> chain = new ArrayList<>();
        KeyStore ks = newKeyStoreForPath(keystorePath);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password != null ? password.toCharArray() : null);
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (cert == null) {
            throw new Exception("Sertifikat sa aliasom " + alias + " nije pronađen u keystore-u " + keystorePath);
        }

        System.out.println("Sertifikat u lancu: " + cert.getIssuerDN());
        chain.add(cert);

        String issuerDN = cert.getIssuerX500Principal().getName();
        String subjectDN = cert.getSubjectX500Principal().getName();

        if (!issuerDN.equals(subjectDN)) {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                X509Certificate potentialParent = (X509Certificate) ks.getCertificate(a);
                if (potentialParent != null &&
                        potentialParent.getSubjectX500Principal().getName().equals(issuerDN)) {
                    chain.addAll(buildCertificateChain(keystorePath, password, a));
                    break;
                }
            }
        }
        return chain;
    }

    private String findAliasForCertificateId(String keystorePath, String password, Long certificateId) {
        if (!isKeystorePath(keystorePath)) {
            // DER/CRT — nema aliasa
            return null;
        }
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            KeyStore ks = newKeyStoreForPath(keystorePath);

            char[] ksPwd = decryptKeystorePasswordIfNeeded(keystorePath, password);
            ks.load(fis, ksPwd);
            if (ksPwd != null) java.util.Arrays.fill(ksPwd, '\0');

            String targetSerialNumber = certificateId.toString();
            Enumeration<String> aliases = ks.aliases();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (ks.isKeyEntry(alias) || ks.isCertificateEntry(alias)) {
                    try {
                        java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
                        if (chain != null && chain.length > 0) {
                            X509Certificate cert = (X509Certificate) chain[0];
                            String certSerialNumber = cert.getSerialNumber().toString();
                            System.out.println("Proveravam alias: " + alias + ", serijski broj: " + certSerialNumber + ", tražim: " + targetSerialNumber);
                            if (targetSerialNumber.equals(certSerialNumber)) {
                                System.out.println("Pronašao odgovarajući alias: " + alias);
                                return alias;
                            }
                        }
                        java.security.cert.Certificate singleCert = ks.getCertificate(alias);
                        if (singleCert instanceof X509Certificate) {
                            X509Certificate x509Cert = (X509Certificate) singleCert;
                            String certSerialNumber = x509Cert.getSerialNumber().toString();
                            if (targetSerialNumber.equals(certSerialNumber)) {
                                System.out.println("Pronašao odgovarajući alias (individual): " + alias);
                                return alias;
                            }
                        }
                    } catch (Exception e) {
                        System.err.println("Greška pri čitanju sertifikata za alias: " + alias + " - " + e.getMessage());
                    }
                }
            }
            System.err.println("Nije pronađen alias za certificate ID: " + certificateId);
            return null;

        } catch (Exception e) {
            System.err.println("Greška pri pronalaženju alias-a: " + e.getMessage());
            return null;
        }
    }

    @Override
    public List<ExtendedCAResponseDTO> getAll() throws Exception {
        List<ExtendedCAResponseDTO> result = new ArrayList<>();
        Set<String> seenSerialNumbers = new HashSet<>();

        System.out.println("Tražim sve sertifikate iz user_certificates tabele...");
        List<UserCertificate> userCertificates = userCertificateRepository.findAll();
        System.out.println("Ukupno UserCertificate entiteta: " + userCertificates.size());

        for (UserCertificate userCert : userCertificates) {
            String path = userCert.getKeystorePath();
            String pwdToken = userCert.getKeystorePassword();

            try {
                if (isDerPath(path)) {
                    try {
                        byte[] der = Files.readAllBytes(Paths.get(path));
                        X509Certificate cert = loadCertificateFromDer(der);
                        String serialNumber = cert.getSerialNumber().toString();
                        if (seenSerialNumbers.add(serialNumber)) {
                            String fileName = Paths.get(path).getFileName().toString();
                            String alias = fileName.replaceFirst("\\.(der|cer|crt)$", "");
                            ExtendedCAResponseDTO response = createExtendedCAResponseDTOFromCert(cert, alias);
                            response.setMessage("End Entity / pojedinačni DER: " + fileName);
                            result.add(response);
                        }
                    } catch (Exception e) {
                        System.err.println("Greška pri čitanju DER fajla: " + path + " - " + e.getMessage());
                    }
                    continue;
                }

                if (isKeystorePath(path)) {
                    String alias = findAliasForCertificateId(path, pwdToken, userCert.getCertificateId());
                    if (alias == null) {
                        continue;
                    }

                    char[] ksPwd = decryptKeystorePasswordIfNeeded(path, pwdToken);
                    try {
                        X509Certificate[] chain = keyStoreReader.readChain(path, ksPwd, alias);

                        if (chain != null && chain.length > 0) {
                            System.out.println("Lanac ima " + chain.length + " sertifikata");
                            for (X509Certificate cert : chain) {
                                String serialNumber = cert.getSerialNumber().toString();
                                if (seenSerialNumbers.add(serialNumber)) {
                                    ExtendedCAResponseDTO response = createExtendedCAResponseDTOFromCert(cert, alias);
                                    result.add(response);
                                }
                            }
                        } else {
                            java.security.cert.Certificate singleCert =
                                    keyStoreReader.readCertificate(path, ksPwd != null ? new String(ksPwd) : null, alias);
                            if (singleCert instanceof X509Certificate) {
                                X509Certificate x509Cert = (X509Certificate) singleCert;
                                String serialNumber = x509Cert.getSerialNumber().toString();
                                if (seenSerialNumbers.add(serialNumber)) {
                                    ExtendedCAResponseDTO response = createExtendedCAResponseDTOFromCert(x509Cert, alias);
                                    result.add(response);
                                }
                            }
                        }
                    } catch (Exception e) {
                        System.err.println("Greška pri čitanju iz keystore-a: " + path + " - " + e.getMessage());
                    } finally {
                        if (ksPwd != null) java.util.Arrays.fill(ksPwd, '\0');
                    }
                    continue;
                }

                System.out.println("Nepoznat tip fajla (nije ni keystore ni DER): " + path);

            } catch (Exception e) {
                System.err.println("Greška pri čitanju sertifikata za UserCertificate ID: " + userCert.getId() +
                        ", greška: " + e.getMessage());
                e.printStackTrace();
            }
        }

        System.out.println("Ukupno pronađeno sertifikata: " + result.size());
        return result;
    }

    @Override
    public List<CAWithValidityDTO> getAllValidCAAliases() throws Exception {
        List<CAWithValidityDTO> validCAAliases = new ArrayList<>();

        System.out.println("Tražim sve validne CA alias-e koji mogu da potpisuju sertifikate...");
        List<UserCertificate> userCertificates = userCertificateRepository.findAll();
        System.out.println("Ukupno UserCertificate entiteta za proveru CA: " + userCertificates.size());

        for (UserCertificate userCert : userCertificates) {
            try {
                String path = userCert.getKeystorePath();
                String password = userCert.getKeystorePassword();

                if (!isKeystorePath(path)) continue;

                String alias = findAliasForCertificateId(path, password, userCert.getCertificateId());
                if (alias == null) continue;

                System.out.println("Proveravam CA validnost za alias: " + alias + " u keystore: " + path);

                char[] ksPwd = decryptKeystorePasswordIfNeeded(path, password);
                try {
                    X509Certificate cert = (X509Certificate) keyStoreReader.readCertificate(
                            path,
                            ksPwd != null ? new String(ksPwd) : null,
                            alias
                    );
                    if (isValidCASigner(cert)) {
                        CAWithValidityDTO caDto = new CAWithValidityDTO(
                                alias,
                                cert.getNotBefore(),
                                cert.getNotAfter()
                        );
                        validCAAliases.add(caDto);
                        System.out.println("✓ Dodao validni CA alias: " + alias + " sa datumima: " +
                                cert.getNotBefore() + " - " + cert.getNotAfter());
                    } else {
                        System.out.println("✗ Alias nije validan CA za potpisivanje: " + alias);
                    }
                } finally {
                    if (ksPwd != null) java.util.Arrays.fill(ksPwd, '\0');
                }

            } catch (Exception e) {
                System.err.println("Greška pri proveri CA alias-a za UserCertificate ID: " + userCert.getId() +
                        ", greška: " + e.getMessage());
            }
        }

        System.out.println("Ukupno pronađeno validnih CA alias-a: " + validCAAliases.size());
        return validCAAliases;
    }

    @Override
    public List<ExtendedCAResponseDTO> getAllEndEntity() throws Exception {
        List<ExtendedCAResponseDTO> result = new ArrayList<>();

        System.out.println("Tražim sve End Entity sertifikate iz end-entity foldera...");

        try {
            Path endEntityDir = Paths.get("src/main/resources/end-entity");

            if (!Files.exists(endEntityDir)) {
                System.out.println("end-entity folder ne postoji");
                return result;
            }

            List<Path> files = Files.list(endEntityDir)
                    .filter(path -> path.toString().toLowerCase(Locale.ROOT).endsWith("_ee.der"))
                    .collect(Collectors.toList());

            for (Path derFile : files) {
                try {
                    System.out.println("Čitam End Entity sertifikat: " + derFile.getFileName());
                    byte[] derBytes = Files.readAllBytes(derFile);
                    X509Certificate cert = loadCertificateFromDer(derBytes);

                    String fileName = derFile.getFileName().toString();
                    String alias = fileName.replace("_ee.der", "").replace(".der", "");

                    ExtendedCAResponseDTO response = createExtendedCAResponseDTOFromCert(cert, alias);
                    response.setMessage("End Entity sertifikat čitan iz DER fajla: " + fileName);

                    result.add(response);
                    System.out.println("✓ Dodao End Entity sertifikat: " + cert.getSubjectDN());

                } catch (Exception e) {
                    System.err.println("Greška pri čitanju End Entity sertifikata " + derFile.getFileName() + ": " + e.getMessage());
                }
            }

        } catch (IOException e) {
            System.err.println("Greška pri pristupanju end-entity folderu: " + e.getMessage());
            throw new Exception("Ne mogu da pristupim end-entity folderu: " + e.getMessage());
        }

        System.out.println("Ukupno pronađeno End Entity sertifikata: " + result.size());
        return result;
    }

    private X509Certificate loadCertificateFromDer(byte[] derBytes) throws Exception {
        try {
            java.security.cert.CertificateFactory certFactory = java.security.cert.CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(derBytes);
            return (X509Certificate) certFactory.generateCertificate(bais);
        } catch (Exception e) {
            throw new Exception("Greška pri učitavanju sertifikata iz DER formata: " + e.getMessage());
        }
    }

    private boolean isValidCASigner(X509Certificate cert) {
        try {
            cert.checkValidity();

            int basicConstraints = cert.getBasicConstraints();
            boolean isCA = basicConstraints != -1;
            if (!isCA) {
                System.out.println("  ✗ Nije CA sertifikat (BasicConstraints = -1)");
                return false;
            }

            boolean[] ku = cert.getKeyUsage();
            if (ku != null) {
                boolean keyCertSign = ku.length > 5 && ku[5];
                boolean cRLSign = ku.length > 6 && ku[6];

                if (!keyCertSign) {
                    System.out.println("  ✗ Nema keyCertSign u KeyUsage");
                    return false;
                }

                System.out.println("  ✓ BasicConstraints CA: " + isCA + ", keyCertSign: " + keyCertSign + ", cRLSign: " + cRLSign);
            } else {
                System.out.println("  ✗ KeyUsage nije postavljen");
                return false;
            }

            return true;

        } catch (Exception e) {
            System.err.println("Greška pri validaciji CA sertifikata: " + e.getMessage());
            return false;
        }
    }

    private CertificateResponse createCertificateResponse(X509Certificate cert, String alias, boolean isLastInChain) throws Exception{
        CertificateResponse response = new CertificateResponse();
        response.setAlias(alias);
        response.setSubjectDN(cert.getSubjectDN().toString());
        response.setIssuerDN(cert.getIssuerDN().toString());
        response.setSerialNumber(cert.getSerialNumber().toString());
        response.setNotBefore(cert.getNotBefore());
        response.setNotAfter(cert.getNotAfter());

        if (cert.getIssuerDN().equals(cert.getSubjectDN())) {
            response.setMessage("Root CA sertifikat (self-signed)");
        } else {
            response.setMessage("Certificate - Issuer: " + cert.getIssuerDN().getName());
        }

        return response;
    }

    private ExtendedCAResponseDTO createIntermediateCAFromExtendedRequest(ExtendedRequest request) throws Exception {
        Long issuerUserId = 1L;

        List<UserCertificate> userCertificates = userCertificateRepository.findByUserId(issuerUserId);
        if (userCertificates.isEmpty()) {
            throw new Exception("Issuer not found!");
        }

        String aliasToFind = request.getIssuerAlias();
        System.out.println("Tražim issuer sa alias-om: " + aliasToFind);
        System.out.println("Ukupno UserCertificate entiteta za user ID " + issuerUserId + ": " + userCertificates.size());

        UserCertificate matchingCertificate = null;

        for (UserCertificate uc : userCertificates) {
            String path = uc.getKeystorePath();
            if (!isKeystorePath(path)) continue;

            System.out.println("Proveravam UserCertificate ID: " + uc.getId() + ", keystore: " + path);
            try (FileInputStream fis = new FileInputStream(path)) {
                KeyStore ks = newKeyStoreForPath(path);
                char[] ksPwd = decryptKeystorePasswordIfNeeded(path, uc.getKeystorePassword());
                ks.load(fis, ksPwd);

                Enumeration<String> aliases = ks.aliases();
                System.out.println("Aliases u keystore-u " + path + ":");
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    System.out.println("  - " + alias + " (tražim: " + aliasToFind + ")");
                }

                if (ks.containsAlias(aliasToFind)) {
                    matchingCertificate = uc;
                    System.out.println("✓ Pronašao matching certificate!");
                    if (ksPwd != null) java.util.Arrays.fill(ksPwd, '\0');
                    break;
                } else {
                    System.out.println("✗ Alias '" + aliasToFind + "' nije pronađen u ovom keystore-u");
                }

                if (ksPwd != null) java.util.Arrays.fill(ksPwd, '\0');

            } catch (Exception e) {
                System.err.println("Greška pri čitanju keystore-a " + path + ": " + e.getMessage());
            }
        }

        if (matchingCertificate == null) {
            throw new Exception("Sertifikat sa aliasom '" + aliasToFind + "' nije pronađen ni u jednom keystore-u korisnika!");
        }

        char[] matchingPwd = decryptKeystorePasswordIfNeeded(matchingCertificate.getKeystorePath(), matchingCertificate.getKeystorePassword());
        String matchingPwdStr = matchingPwd != null ? new String(matchingPwd) : null;

        X509Certificate issuerCert = (X509Certificate) keyStoreReader.readCertificate(
                matchingCertificate.getKeystorePath(),
                matchingPwdStr,
                request.getIssuerAlias()
        );

        Issuer issuer = keyStoreReader.readIssuerFromStore(
                matchingCertificate.getKeystorePath(),
                request.getIssuerAlias(),
                matchingPwdStr != null ? matchingPwdStr.toCharArray() : null,
                matchingPwdStr != null ? matchingPwdStr.toCharArray() : null
        );

        if (matchingPwd != null) java.util.Arrays.fill(matchingPwd, '\0');

        Date startDate = request.getStartDate() != null
                ? Date.from(request.getStartDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
                : new Date();
        Date endDate = request.getEndDate() != null
                ? Date.from(request.getEndDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
                : new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));

        String serialNumber = (request.getSerialNumber() != null && !request.getSerialNumber().trim().isEmpty())
                ? request.getSerialNumber()
                : SerialNumberUtil.generateSerial(32).toString();

        KeyPair keyPair = generateKeyPair();

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, request.getCommonName());
        builder.addRDN(BCStyle.O, request.getOrganization());
        builder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, request.getCountry());
        builder.addRDN(BCStyle.E, request.getEmail());

        Subject subject = new Subject(keyPair.getPublic(), builder.build());

        X509Certificate intermediateCA = caCertificateGenerator.generateIntermediateCACertificate(
                subject,
                issuer,
                issuerCert,
                startDate,
                endDate,
                serialNumber,
                request.getPathLength(),
                request.getKeyUsages(),
                request.getExtendedKeyUsages(),
                request.getSanList(),
                request.getAdditionalExtensions()
        );

        String keystorePathToUse = matchingCertificate.getKeystorePath();
        String keyStorePassword = matchingPwdStr;

        boolean issuerHasChildren = CertificateUtils.issuerHasChildren(
                issuerCert,
                matchingCertificate.getKeystorePath(),
                matchingPwdStr != null ? matchingPwdStr.toCharArray() : null
        );

        if (issuerHasChildren) {
            keyStorePassword = PasswordGenerator.generatePassword(20);
            String newAlias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase(Locale.ROOT);
            keystorePathToUse = "src/main/resources/static/" + newAlias + ".jks";
            keyStoreWriter.loadKeyStore(null, keyStorePassword.toCharArray());
            keyStoreWriter.saveKeyStore(keystorePathToUse, keyStorePassword.toCharArray());
        } else {
            keyStoreWriter.loadKeyStore(keystorePathToUse, keyStorePassword != null ? keyStorePassword.toCharArray() : null);
        }

        String alias = request.getCommonName().replaceAll("\\s+", "-").toLowerCase(Locale.ROOT);
        List<X509Certificate> chainList = buildCertificateChain(
                matchingCertificate.getKeystorePath(),
                matchingPwdStr != null ? matchingPwdStr : "",
                request.getIssuerAlias()
        );
        chainList.add(0, intermediateCA);
        X509Certificate[] chain = chainList.toArray(new X509Certificate[0]);

        keyStoreWriter.writeChain(alias, keyPair.getPrivate(), keyStorePassword.toCharArray(), chain);
        keyStoreWriter.saveKeyStore(keystorePathToUse, keyStorePassword.toCharArray());

        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));

        SecretKey kek = kekService.getOrCreateKek(user.getId());
        byte[] aad = ("keystore:" + aliasFromKeystorePath(keystorePathToUse)).getBytes(StandardCharsets.UTF_8);

        AesGcmService.EncBlob blob = aesGcmService.encryptBytesWithKey(
                kek,
                keyStorePassword.getBytes(StandardCharsets.UTF_8),
                aad
        );

        String encToken = "v1:" +
                Base64.getEncoder().encodeToString(blob.getIv()) + ":" +
                Base64.getEncoder().encodeToString(blob.getCt());

        UserCertificate userCertificate = new UserCertificate(
                user,
                Long.parseLong(serialNumber),
                encToken,
                keystorePathToUse
        );
        userCertificateRepository.save(userCertificate);

        ExtendedCAResponseDTO response = createExtendedCAResponseDTO(intermediateCA, alias, request, request.getIssuerAlias());
        response.setMessage("Intermediate CA uspešno kreiran i lozinka sačuvana u bazi!");
        return response;
    }

    private ExtendedCAResponseDTO createExtendedCAResponseDTO(X509Certificate cert, String alias, ExtendedRequest request, String issuerAlias) throws Exception {
        ExtendedCAResponseDTO response = new ExtendedCAResponseDTO();

        response.setAlias(alias);
        response.setIssuerAlias(issuerAlias);

        response.setSubjectDN(cert.getSubjectDN().toString());
        response.setCommonName(request.getCommonName());
        response.setOrganization(request.getOrganization());
        response.setOrganizationalUnit(request.getOrganizationalUnit());
        response.setCountry(request.getCountry());
        response.setEmail(request.getEmail());

        response.setIssuerDN(cert.getIssuerDN().toString());

        response.setSerialNumber(cert.getSerialNumber().toString());
        response.setNotBefore(cert.getNotBefore());
        response.setNotAfter(cert.getNotAfter());

        if (request.getTtlDays() != null) {
            response.setTtlDays(request.getTtlDays());
        } else if (cert.getNotBefore() != null && cert.getNotAfter() != null) {
            long ttlMillis = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
            response.setTtlDays(ttlMillis / (24 * 60 * 60 * 1000));
        }

        response.setIsCA(request.getIsCA() != null ? request.getIsCA() : true);
        response.setPathLength(request.getPathLength());

        response.setSanList(request.getSanList());
        response.setKeyUsages(request.getKeyUsages());
        response.setExtendedKeyUsages(request.getExtendedKeyUsages());
        response.setAdditionalExtensions(request.getAdditionalExtensions());

        response.setCertificatePEM(Base64.getEncoder().encodeToString(cert.getEncoded()));

        try {
            response.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
            if (cert.getPublicKey().getAlgorithm().equals("RSA")) {
                response.setPublicKeySize(cert.getPublicKey().getEncoded().length * 8);
            }
            response.setSignatureAlgorithm(cert.getSigAlgName());
        } catch (Exception e) {
            System.err.println("Greška pri čitanju public key/signature informacija: " + e.getMessage());
        }

        return response;
    }

    private ExtendedCAResponseDTO createExtendedCAResponseDTOFromCert(X509Certificate cert, String alias) throws Exception {
        ExtendedCAResponseDTO response = new ExtendedCAResponseDTO();

        response.setAlias(alias);
        response.setIssuerAlias(null);

        response.setSubjectDN(cert.getSubjectDN().toString());

        String subjectDN = cert.getSubjectDN().toString();
        response.setCommonName(extractFieldFromDN(subjectDN, "CN"));
        response.setOrganization(extractFieldFromDN(subjectDN, "O"));
        response.setOrganizationalUnit(extractFieldFromDN(subjectDN, "OU"));
        response.setCountry(extractFieldFromDN(subjectDN, "C"));
        response.setEmail(extractFieldFromDN(subjectDN, "E"));

        response.setIssuerDN(cert.getIssuerDN().toString());

        response.setSerialNumber(cert.getSerialNumber().toString());
        response.setNotBefore(cert.getNotBefore());
        response.setNotAfter(cert.getNotAfter());

        if (cert.getNotBefore() != null && cert.getNotAfter() != null) {
            long ttlMillis = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
            response.setTtlDays(ttlMillis / (24 * 60 * 60 * 1000));
        }

        int basicConstraints = cert.getBasicConstraints();
        response.setIsCA(basicConstraints != -1);
        response.setPathLength(basicConstraints >= 0 ? basicConstraints : null);

        response.setCertificatePEM(Base64.getEncoder().encodeToString(cert.getEncoded()));

        try {
            response.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
            if (cert.getPublicKey().getAlgorithm().equals("RSA")) {
                response.setPublicKeySize(cert.getPublicKey().getEncoded().length * 8);
            }
            response.setSignatureAlgorithm(cert.getSigAlgName());
        } catch (Exception e) {
            System.err.println("Greška pri čitanju public key/signature informacija: " + e.getMessage());
        }

        if (cert.getIssuerDN().equals(cert.getSubjectDN())) {
            response.setMessage("Root CA sertifikat (self-signed)");
        } else {
            response.setMessage("Certificate - Issuer: " + cert.getIssuerDN().getName());
        }

        return response;
    }

    private String extractFieldFromDN(String dn, String fieldName) {
        try {
            String[] pairs = dn.split(",");
            for (String pair : pairs) {
                String[] keyValue = pair.trim().split("=");
                if (keyValue.length == 2 && keyValue[0].trim().equals(fieldName)) {
                    return keyValue[1].trim();
                }
            }
        } catch (Exception e) { }
        return null;
    }

    private ExtendedCAResponseDTO createEndEntityCertificate(ExtendedRequest request) throws Exception {
        System.out.println("=== KREIRANJE END ENTITY SERTIFIKATA ===");

        KeyPair keyPair = generateKeyPair();

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, request.getCommonName());
        if (request.getOrganization() != null) {
            builder.addRDN(BCStyle.O, request.getOrganization());
        }
        if (request.getOrganizationalUnit() != null) {
            builder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        }
        if (request.getCountry() != null) {
            builder.addRDN(BCStyle.C, request.getCountry());
        }
        if (request.getEmail() != null) {
            builder.addRDN(BCStyle.E, request.getEmail());
        }

        Subject subject = new Subject(keyPair.getPublic(), builder.build());

        List<UserCertificate> userCertificates = userCertificateRepository.findByUserId(1L);
        if (userCertificates.isEmpty()) {
            throw new Exception("Nema dostupnih CA sertifikata za potpisivanje End Entity sertifikata!");
        }

        UserCertificate caCertificate = null;
        for (UserCertificate uc : userCertificates) {
            try {
                String keystorePath = uc.getKeystorePath();
                if (!isKeystorePath(keystorePath)) continue;

                String password = uc.getKeystorePassword();
                String alias = findAliasForCertificateId(keystorePath, password, uc.getCertificateId());

                if (alias != null) {
                    char[] ksPwd = decryptKeystorePasswordIfNeeded(keystorePath, password);
                    X509Certificate cert = (X509Certificate) keyStoreReader.readCertificate(keystorePath, ksPwd != null ? new String(ksPwd) : null, alias);
                    if (isValidCASigner(cert)) {
                        caCertificate = uc;
                        System.out.println("Pronašao valjani CA sertifikat za potpisivanje: " + alias);
                        if (ksPwd != null) java.util.Arrays.fill(ksPwd, '\0');
                        break;
                    }
                    if (ksPwd != null) java.util.Arrays.fill(ksPwd, '\0');
                }
            } catch (Exception e) {
                System.err.println("Greška pri proveri CA sertifikata: " + e.getMessage());
            }
        }

        if (caCertificate == null) {
            throw new Exception("Nema valjanih CA sertifikata za potpisivanje End Entity sertifikata!");
        }

        String caAlias = findAliasForCertificateId(caCertificate.getKeystorePath(),
                caCertificate.getKeystorePassword(),
                caCertificate.getCertificateId());

        if (caAlias == null) {
            throw new Exception("Ne mogu da pronađem alias za CA sertifikat!");
        }

        char[] caPwd = decryptKeystorePasswordIfNeeded(
                caCertificate.getKeystorePath(),
                caCertificate.getKeystorePassword()
        );
        String caPwdStr = caPwd != null ? new String(caPwd) : null;

        Issuer issuer = keyStoreReader.readIssuerFromStore(
                caCertificate.getKeystorePath(),
                caAlias,
                caPwdStr != null ? caPwdStr.toCharArray() : null,
                caPwdStr != null ? caPwdStr.toCharArray() : null
        );

        X509Certificate issuerCert = (X509Certificate) keyStoreReader.readCertificate(
                caCertificate.getKeystorePath(),
                caPwdStr,
                caAlias
        );
        if (caPwd != null) java.util.Arrays.fill(caPwd, '\0');

        if (issuer == null || issuerCert == null) {
            throw new Exception("Ne mogu da učitam CA sertifikat za potpisivanje!");
        }

        System.out.println("Koristim CA sertifikat: " + issuerCert.getSubjectDN());

        Date startDate = request.getStartDate() != null
                ? Date.from(request.getStartDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
                : new Date();
        Date endDate = request.getEndDate() != null
                ? Date.from(request.getEndDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
                : new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));

        String serialNumber = (request.getSerialNumber() != null && !request.getSerialNumber().trim().isEmpty())
                ? request.getSerialNumber()
                : SerialNumberUtil.generateSerial(32).toString();

        X509Certificate endEntityCert = caCertificateGenerator.generateEndEntityCertificate(
                subject,
                issuer,
                issuerCert,
                startDate,
                endDate,
                serialNumber
        );

        String cn = request.getCommonName();
        if (cn == null || cn.trim().isEmpty()) {
            cn = "end-entity";
        }
        String safeFile = cn.replaceAll("[^a-zA-Z0-9._-]", "_");

        Path outDir = Paths.get("src/main/resources/end-entity");
        Files.createDirectories(outDir);

        Path certPath = outDir.resolve(safeFile + "_ee.der");
        writeCertificateDer(endEntityCert, certPath);

        System.out.println("End Entity sertifikat sačuvan u: " + certPath);

        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));

        UserCertificate userCertificate = new UserCertificate(
                user,
                Long.parseLong(serialNumber),
                null,
                certPath.toString()
        );
        userCertificateRepository.save(userCertificate);

        ExtendedCAResponseDTO response = createExtendedCAResponseDTO(endEntityCert, safeFile, request, null);
        response.setMessage("End Entity sertifikat uspešno kreiran i sačuvan u DER formatu: " + certPath);

        return response;
    }

    private void writeCertificateDer(X509Certificate cert, Path path) throws IOException, CertificateEncodingException {
        byte[] der = cert.getEncoded();
        Files.write(path, der, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }
}
