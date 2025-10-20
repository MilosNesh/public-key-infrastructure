package com.pki.example.serviceImpl;

import com.pki.example.certificates.CACertificateGenerator;
import com.pki.example.data.*;
import com.pki.example.domain.UserCertificate;
import com.pki.example.dto.ExtendedCAResponseDTO;
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
import java.security.KeyStore;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    public ExtendedCAResponseDTO createRootCA(ExtendedRequest request) throws Exception {

        System.out.println("Issuerrrr: " + request.getIssuerAlias());
        // Proveri da li je Intermediate CA (ima issuerAlias) ili Root CA
        if (request.getIssuerAlias() != null && !request.getIssuerAlias().trim().isEmpty()) {
            // Ovo je Intermediate CA - pozovi logiku za Intermediate CA
            return createIntermediateCAFromExtendedRequest(request);
        }
        
        // Root CA logika - self-signed
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

        // Konvertovanje LocalDate u Date
        Date startDate = request.getStartDate() != null 
            ? Date.from(request.getStartDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
            : new Date();
        Date endDate = request.getEndDate() != null 
            ? Date.from(request.getEndDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
            : new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)); // +1 godina default

        // Koristimo serialNumber iz request-a ili generišemo novi
        String serialNumber = (request.getSerialNumber() != null && !request.getSerialNumber().trim().isEmpty())
            ? request.getSerialNumber()
            : SerialNumberUtil.generateSerial(32).toString();
        
        // 4. Generisanje Root CA sertifikata
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
            Long.parseLong(serialNumber),
            keyStorePassword,  // Plain text lozinka (TODO: šifrovati kasnije)
            keystorePath
        );
        userCertificateRepository.save(userCertificate);

        // 9. Response - kreiranje ExtendedCAResponseDTO
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
        System.out.println("Proveravam issuer sertifikat: ");
        System.out.println("  Subject: " + issuerCert.getSubjectDN());
        System.out.println("  Issuer: " + issuerCert.getIssuerDN());
        System.out.println("  Serial: " + issuerCert.getSerialNumber());
        System.out.println("  BasicConstraints: " + issuerCert.getBasicConstraints());
        System.out.println("  KeyUsage: " + java.util.Arrays.toString(issuerCert.getKeyUsage()));
        
        if (!validator.isCAValid(issuerCert, parentOrNull)) {
            throw new Exception("Issuer certificate not valid! Proverite BasicConstraints, KeyUsage ili period važenja.");
        }

        // Konvertovanje LocalDate u Date
        Date startDate = request.getStartDate() != null 
            ? Date.from(request.getStartDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
            : new Date();
        Date endDate = request.getEndDate() != null 
            ? Date.from(request.getEndDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
            : new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)); // +1 godina default

        // PROVERA PERIODA:
        if (!validator.canIssue(issuerCert, startDate, endDate, parentOrNull)) {
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

        // Koristimo serialNumber iz request-a ili generišemo novi
        String serialNumber = (request.getSerialNumber() != null && !request.getSerialNumber().trim().isEmpty())
            ? request.getSerialNumber()
            : SerialNumberUtil.generateSerial(32).toString();

        // 7. Generisanje Intermediate CA sertifikata
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
        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));
        UserCertificate userCertificate = new UserCertificate(
                user,
                Long.parseLong(serialNumber),
                keyStorePassword,
                keystorePathToUse
        );
        userCertificateRepository.save(userCertificate);

        // 11. Response - kreiranje ExtendedCAResponseDTO
        ExtendedCAResponseDTO response = createExtendedCAResponseDTO(intermediateCA, alias, request, request.getIssuerAlias());
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

    /**
     * Pokušava da pronađe alias za specifični certificate ID u keystore-u
     */
    private String findAliasForCertificateId(String keystorePath, String password, Long certificateId) {
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(fis, password.toCharArray());
            
            String targetSerialNumber = certificateId.toString();
            Enumeration<String> aliases = ks.aliases();
            
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (ks.isKeyEntry(alias)) {
                    try {
                        // Proveri certificate u lancu (prvi u lancu je subject certificate)
                        java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
                        if (chain != null && chain.length > 0) {
                            X509Certificate cert = (X509Certificate) chain[0]; // prvi u lancu
                            String certSerialNumber = cert.getSerialNumber().toString();
                            System.out.println("Proveravam alias: " + alias + ", serijski broj: " + certSerialNumber + ", tražim: " + targetSerialNumber);
                            
                            if (targetSerialNumber.equals(certSerialNumber)) {
                                System.out.println("Pronašao odgovarajući alias: " + alias);
                                return alias;
                            }
                        }
                        
                        // Takođe proveri individualni certificate (fallback)
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
    

    /**
     * Proverava da li je sertifikat intermediate sertifikat izdato od specifičnog root-a
     */
    private boolean isIntermediateCertificateForRoot(X509Certificate cert, String rootSubjectDN) {
        try {
            String certIssuerDN = cert.getIssuerDN().toString();
            String certSubjectDN = cert.getSubjectDN().toString();
            
            System.out.println("Proveravam da li je intermediate:");
            System.out.println("  Root Subject DN: " + rootSubjectDN);
            System.out.println("  Cert Issuer DN:  " + certIssuerDN);
            System.out.println("  Cert Subject DN: " + certSubjectDN);
            
            // Intermediate sertifikat mora biti izdato od root-a (issuerDN = rootSubjectDN)
            // i ne sme biti self-signed
            boolean issuerMatches = rootSubjectDN.equals(certIssuerDN);
            boolean notSelfSigned = !certIssuerDN.equals(certSubjectDN);
            
            System.out.println("  Issuer matches root: " + issuerMatches);
            System.out.println("  Not self-signed: " + notSelfSigned);
            
            boolean isIntermediateForRoot = issuerMatches && notSelfSigned;
            System.out.println("  Is intermediate: " + isIntermediateForRoot);
            
            return isIntermediateForRoot;
            
        } catch (Exception e) {
            System.err.println("Greška pri proveri intermediate sertifikata: " + e.getMessage());
            return false;
        }
    }

    @Override
    public List<ExtendedCAResponseDTO> getAll() throws Exception {
        List<ExtendedCAResponseDTO> result = new ArrayList<>();
        Set<String> seenSerialNumbers = new HashSet<>();
        
        System.out.println("Tražim sve sertifikate iz user_certificates tabele...");
        
        // Uzmi sve UserCertificate entitete
        List<UserCertificate> userCertificates = userCertificateRepository.findAll();
        System.out.println("Ukupno UserCertificate entiteta: " + userCertificates.size());
        
        for (UserCertificate userCert : userCertificates) {
            try {
                String keystorePath = userCert.getKeystorePath();
                String password = userCert.getKeystorePassword();
                String alias = findAliasForCertificateId(keystorePath, password, userCert.getCertificateId());
                
                if (alias != null) {
                    System.out.println("Proveravam alias: " + alias + " u keystore: " + keystorePath);
                    
                    // Prvo proveri lanac sertifikata
                    X509Certificate[] chain = keyStoreReader.readChain(keystorePath, password.toCharArray(), alias);
                    
                    if (chain != null && chain.length > 0) {
                        System.out.println("Lanac ima " + chain.length + " sertifikata");
                        
                        // Dodaj sve sertifikate iz lanca
                        for (int i = 0; i < chain.length; i++) {
                            X509Certificate cert = chain[i];
                            String serialNumber = cert.getSerialNumber().toString();
                            
                            if (!seenSerialNumbers.contains(serialNumber)) {
                                seenSerialNumbers.add(serialNumber);
                                
                                ExtendedCAResponseDTO response = createExtendedCAResponseDTOFromCert(cert, alias);
                                result.add(response);
                                
                                System.out.println("Dodao sertifikat " + (i + 1) + " iz lanca: " + cert.getSubjectDN());
                            }
                        }
                    }
                    
                    // Takođe proveri individualni sertifikat (možda nije u lancu)
                    try {
                        java.security.cert.Certificate singleCert = keyStoreReader.readCertificate(keystorePath, password, alias);
                        if (singleCert instanceof X509Certificate) {
                            X509Certificate x509Cert = (X509Certificate) singleCert;
                            String serialNumber = x509Cert.getSerialNumber().toString();
                            
                            if (!seenSerialNumbers.contains(serialNumber)) {
                                seenSerialNumbers.add(serialNumber);
                                
                                ExtendedCAResponseDTO response = createExtendedCAResponseDTOFromCert(x509Cert, alias);
                                result.add(response);
                                
                                System.out.println("Dodao individualni sertifikat: " + x509Cert.getSubjectDN());
                            }
                        }
                    } catch (Exception e) {
                        System.out.println("Nema individualnog sertifikata za alias: " + alias);
                    }
                }
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
    public List<String> getAllValidCAAliases() throws Exception {
        List<String> validCAAliases = new ArrayList<>();
        
        System.out.println("Tražim sve validne CA alias-e koji mogu da potpisuju sertifikate...");
        
        // Uzmi sve UserCertificate entitete
        List<UserCertificate> userCertificates = userCertificateRepository.findAll();
        System.out.println("Ukupno UserCertificate entiteta za proveru CA: " + userCertificates.size());
        
        for (UserCertificate userCert : userCertificates) {
            try {
                String keystorePath = userCert.getKeystorePath();
                String password = userCert.getKeystorePassword();
                String alias = findAliasForCertificateId(keystorePath, password, userCert.getCertificateId());
                
                if (alias != null) {
                    System.out.println("Proveravam CA validnost za alias: " + alias + " u keystore: " + keystorePath);
                    
                    try {
                        // Učitaj sertifikat
                        X509Certificate cert = (X509Certificate) keyStoreReader.readCertificate(keystorePath, password, alias);
                        
                        // Proveri da li je valjan CA sertifikat
                        if (isValidCASigner(cert)) {
                            validCAAliases.add(alias);
                            System.out.println("✓ Dodao validni CA alias: " + alias);
                        } else {
                            System.out.println("✗ Alias nije validan CA za potpisivanje: " + alias);
                        }
                        
                    } catch (Exception e) {
                        System.err.println("Greška pri čitanju sertifikata za alias " + alias + ": " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                System.err.println("Greška pri proveri CA alias-a za UserCertificate ID: " + userCert.getId() + 
                                 ", greška: " + e.getMessage());
            }
        }
        
        System.out.println("Ukupno pronađeno validnih CA alias-a: " + validCAAliases.size());
        return validCAAliases;
    }

    /**
     * Pomoćna metoda za proveru da li sertifikat može da potpisuje druge sertifikate (CA)
     */
    private boolean isValidCASigner(X509Certificate cert) {
        try {
            // 1. Proveri period važenja
            cert.checkValidity();
            
            // 2. Proveri BasicConstraints - mora biti CA
            int basicConstraints = cert.getBasicConstraints();
            boolean isCA = basicConstraints != -1;
            if (!isCA) {
                System.out.println("  ✗ Nije CA sertifikat (BasicConstraints = -1)");
                return false;
            }
            
            // 3. Proveri KeyUsage - mora imati keyCertSign
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
            
            // 4. TODO: Proveri CRL status (trenutno nije implementirano)
            // Ovde bi trebalo dodati proveru CRL liste da vidimo da li je sertifikat povučen
            
            return true;
            
        } catch (Exception e) {
            System.err.println("Greška pri validaciji CA sertifikata: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Pomoćna metoda za kreiranje CertificateResponse objekta
     */
    private CertificateResponse createCertificateResponse(X509Certificate cert, String alias, boolean isLastInChain) throws Exception{
        CertificateResponse response = new CertificateResponse();
        response.setAlias(alias);
        response.setSubjectDN(cert.getSubjectDN().toString());
        response.setIssuerDN(cert.getIssuerDN().toString());
        response.setSerialNumber(cert.getSerialNumber().toString());
        response.setNotBefore(cert.getNotBefore());
        response.setNotAfter(cert.getNotAfter());

        // Dodaj opis tipa sertifikata
        if (cert.getIssuerDN().equals(cert.getSubjectDN())) {
            response.setMessage("Root CA sertifikat (self-signed)");
        } else {
            response.setMessage("Certificate - Issuer: " + cert.getIssuerDN().getName());
        }
        
        return response;
    }

    /**
     * Pomocna metoda za kreiranje Intermediate CA iz ExtendedRequest
     */
    private ExtendedCAResponseDTO createIntermediateCAFromExtendedRequest(ExtendedRequest request) throws Exception {
        // Koristimo ID=1 kao default issuer user
        Long issuerUserId = 1L;
        
        List<UserCertificate> userCertificates = userCertificateRepository.findByUserId(issuerUserId);

        if (userCertificates.size() == 0) {
            throw new Exception("Issuer not found!");
        }

        String aliasToFind = request.getIssuerAlias();
        System.out.println("Tražim issuer sa alias-om: " + aliasToFind);
        System.out.println("Ukupno UserCertificate entiteta za user ID " + issuerUserId + ": " + userCertificates.size());
        
        UserCertificate matchingCertificate = null;

        for (UserCertificate uc : userCertificates) {
            System.out.println("Proveravam UserCertificate ID: " + uc.getId() + ", keystore: " + uc.getKeystorePath());
            try (FileInputStream fis = new FileInputStream(uc.getKeystorePath())) {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(fis, uc.getKeystorePassword().toCharArray());

                // Lista svi alias-e
                Enumeration<String> aliases = ks.aliases();
                System.out.println("Aliases u keystore-u " + uc.getKeystorePath() + ":");
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    System.out.println("  - " + alias + " (tražim: " + aliasToFind + ")");
                }

                if (ks.containsAlias(aliasToFind)) {
                    matchingCertificate = uc;
                    System.out.println("✓ Pronašao matching certificate!");
                    break;
                } else {
                    System.out.println("✗ Alias '" + aliasToFind + "' nije pronađen u ovom keystore-u");
                }

            } catch (Exception e) {
                System.err.println("Greška pri čitanju keystore-a " + uc.getKeystorePath() + ": " + e.getMessage());
            }
        }

        if (matchingCertificate == null) {
            throw new Exception("Sertifikat sa aliasom '" + aliasToFind + "' nije pronađen ni u jednom keystore-u korisnika!");
        }

        // Učitavanje issuer sertifikata
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

        // Konvertovanje LocalDate u Date
        Date startDate = request.getStartDate() != null 
            ? Date.from(request.getStartDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
            : new Date();
        Date endDate = request.getEndDate() != null 
            ? Date.from(request.getEndDate().atStartOfDay(ZoneId.systemDefault()).toInstant())
            : new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000));

        String serialNumber = (request.getSerialNumber() != null && !request.getSerialNumber().trim().isEmpty())
            ? request.getSerialNumber()
            : SerialNumberUtil.generateSerial(32).toString();

        // Generisanje ključeva za novi CA
        KeyPair keyPair = generateKeyPair();

        // Kreiranje X500Name za novi CA
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, request.getCommonName());
        builder.addRDN(BCStyle.O, request.getOrganization());
        builder.addRDN(BCStyle.OU, request.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, request.getCountry());
        builder.addRDN(BCStyle.E, request.getEmail());

        Subject subject = new Subject(keyPair.getPublic(), builder.build());

        // Generisanje Intermediate CA sertifikata
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

        // Generisanje random lozinke za privatni ključ
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

        // Čuvanje u bazi
        User user = userRepository.findById(1L)
                .orElseThrow(() -> new RuntimeException("User sa ID=1 nije pronađen u bazi"));
        UserCertificate userCertificate = new UserCertificate(
                user,
                Long.parseLong(serialNumber),
                keyStorePassword,
                keystorePathToUse
        );
        userCertificateRepository.save(userCertificate);

        // Response - kreiranje ExtendedCAResponseDTO
        ExtendedCAResponseDTO response = createExtendedCAResponseDTO(intermediateCA, alias, request, request.getIssuerAlias());
        response.setMessage("Intermediate CA uspešno kreiran i lozinka sačuvana u bazi!");

        return response;
    }

    /**
     * Pomoćna metoda za kreiranje ExtendedCAResponseDTO objekta
     */
    private ExtendedCAResponseDTO createExtendedCAResponseDTO(X509Certificate cert, String alias, ExtendedRequest request, String issuerAlias) throws Exception {
        ExtendedCAResponseDTO response = new ExtendedCAResponseDTO();
        
        // Osnovni podaci
        response.setAlias(alias);
        response.setIssuerAlias(issuerAlias); // null za Root CA, vrednost za Intermediate CA
        
        // Subject DN i izdvojena polja
        response.setSubjectDN(cert.getSubjectDN().toString());
        response.setCommonName(request.getCommonName());
        response.setOrganization(request.getOrganization());
        response.setOrganizationalUnit(request.getOrganizationalUnit());
        response.setCountry(request.getCountry());
        response.setEmail(request.getEmail());
        
        // Issuer DN
        response.setIssuerDN(cert.getIssuerDN().toString());
        
        // Serial i validnost
        response.setSerialNumber(cert.getSerialNumber().toString());
        response.setNotBefore(cert.getNotBefore());
        response.setNotAfter(cert.getNotAfter());
        
        // TTL Days - izračunaj iz datuma
        if (request.getTtlDays() != null) {
            response.setTtlDays(request.getTtlDays());
        } else if (cert.getNotBefore() != null && cert.getNotAfter() != null) {
            long ttlMillis = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
            response.setTtlDays(ttlMillis / (24 * 60 * 60 * 1000));
        }
        
        // CA info
        response.setIsCA(request.getIsCA() != null ? request.getIsCA() : true);
        response.setPathLength(request.getPathLength());
        
        // SAN, key usages i ekstenzije
        response.setSanList(request.getSanList());
        response.setKeyUsages(request.getKeyUsages());
        response.setExtendedKeyUsages(request.getExtendedKeyUsages());
        response.setAdditionalExtensions(request.getAdditionalExtensions());
        
        // Certificate PEM
        response.setCertificatePEM(Base64.getEncoder().encodeToString(cert.getEncoded()));
        
        // Public key i signature info
        try {
            response.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
            if (cert.getPublicKey().getAlgorithm().equals("RSA")) {
                response.setPublicKeySize(cert.getPublicKey().getEncoded().length * 8); // gruba aproksimacija
            }
            response.setSignatureAlgorithm(cert.getSigAlgName());
        } catch (Exception e) {
            // Nema kritične greške ako ne možemo da dobijemo ove informacije
            System.err.println("Greška pri čitanju public key/signature informacija: " + e.getMessage());
        }
        
        return response;
    }

    /**
     * Pomoćna metoda za kreiranje ExtendedCAResponseDTO objekta direktno iz X509Certificate
     * bez potrebe za ExtendedRequest objektom (koristi se u getAll metodi)
     */
    private ExtendedCAResponseDTO createExtendedCAResponseDTOFromCert(X509Certificate cert, String alias) throws Exception {
        ExtendedCAResponseDTO response = new ExtendedCAResponseDTO();
        
        // Osnovni podaci
        response.setAlias(alias);
        response.setIssuerAlias(null); // Ne znamo issuer alias u getAll metodi
        
        // Subject DN - pokušaj da izvučeš osnovna polja iz subject DN-a
        response.setSubjectDN(cert.getSubjectDN().toString());
        
        // Razdvoj Subject DN na osnovna polja
        String subjectDN = cert.getSubjectDN().toString();
        response.setCommonName(extractFieldFromDN(subjectDN, "CN"));
        response.setOrganization(extractFieldFromDN(subjectDN, "O"));
        response.setOrganizationalUnit(extractFieldFromDN(subjectDN, "OU"));
        response.setCountry(extractFieldFromDN(subjectDN, "C"));
        response.setEmail(extractFieldFromDN(subjectDN, "E"));
        
        // Issuer DN
        response.setIssuerDN(cert.getIssuerDN().toString());
        
        // Serial i validnost
        response.setSerialNumber(cert.getSerialNumber().toString());
        response.setNotBefore(cert.getNotBefore());
        response.setNotAfter(cert.getNotAfter());
        
        // TTL Days - izračunaj iz datuma
        if (cert.getNotBefore() != null && cert.getNotAfter() != null) {
            long ttlMillis = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
            response.setTtlDays(ttlMillis / (24 * 60 * 60 * 1000));
        }
        
        // CA info - odredi na osnovu BasicConstraints
        int basicConstraints = cert.getBasicConstraints();
        response.setIsCA(basicConstraints != -1);
        response.setPathLength(basicConstraints >= 0 ? basicConstraints : null);
        
        // Certificate PEM
        response.setCertificatePEM(Base64.getEncoder().encodeToString(cert.getEncoded()));
        
        // Public key i signature info
        try {
            response.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
            if (cert.getPublicKey().getAlgorithm().equals("RSA")) {
                response.setPublicKeySize(cert.getPublicKey().getEncoded().length * 8); // gruba aproksimacija
            }
            response.setSignatureAlgorithm(cert.getSigAlgName());
        } catch (Exception e) {
            // Nema kritične greške ako ne možemo da dobijemo ove informacije
            System.err.println("Greška pri čitanju public key/signature informacija: " + e.getMessage());
        }
        
        // Dodaj opis tipa sertifikata
        if (cert.getIssuerDN().equals(cert.getSubjectDN())) {
            response.setMessage("Root CA sertifikat (self-signed)");
        } else {
            response.setMessage("Certificate - Issuer: " + cert.getIssuerDN().getName());
        }
        
        return response;
    }
    
    /**
     * Pomoćna metoda za izvlačenje određenog polja iz Distinguished Name stringa
     */
    private String extractFieldFromDN(String dn, String fieldName) {
        try {
            String[] pairs = dn.split(",");
            for (String pair : pairs) {
                String[] keyValue = pair.trim().split("=");
                if (keyValue.length == 2 && keyValue[0].trim().equals(fieldName)) {
                    return keyValue[1].trim();
                }
            }
        } catch (Exception e) {
            // Ako ne možemo da parsujemo DN, vratimo null
        }
        return null;
    }

}

