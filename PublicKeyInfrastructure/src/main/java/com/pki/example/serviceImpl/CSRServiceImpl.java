package com.pki.example.serviceImpl;

import com.pki.example.certificates.CACertificateGenerator;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.Issuer;
import com.pki.example.domain.CsrRequest;
import com.pki.example.domain.UserCertificate;
import com.pki.example.keystores.KeyStoreReader;
import com.pki.example.keystores.KeyStoreWriter;
import com.pki.example.repository.CsrRepository;
import com.pki.example.repository.UserCertificateRepository;
import com.pki.example.service.CSRService;
import com.pki.example.util.SerialNumberUtil;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;


@Service
public class CSRServiceImpl implements CSRService {


    @Autowired
    private CACertificateGenerator caCertificateGenerator;

    @Autowired
    private KeyStoreWriter keyStoreWriter;

    @Autowired
    private KeyStoreReader keyStoreReader;

    @Autowired
    private CsrRepository csrRepository;

    @Autowired
    private UserCertificateRepository userCertificateRepository;


    @Override
    public CertificateResponse approveCSR(Long csrId, Long issuerUserId, String issuerAlias) throws Exception{
        System.out.println("CSR id: " + csrId);
        CsrRequest request = csrRepository.findById(csrId)
                .orElseThrow(() -> new IllegalArgumentException("CSR not found"));

        if (!request.getStatus().equals("pending")) {
            throw new IllegalStateException("CSR already processed");
        }

        // 1. Učitaj CSR fajl
        Path csrPath = Paths.get(request.getCsrPath());
        PKCS10CertificationRequest csr = loadCSR(Files.readAllBytes(csrPath));

        // 2) Pripremi issuer (CA) i issuer cert iz keystorea
        List<UserCertificate> userCertificates = userCertificateRepository.findByUserId(issuerUserId);

        if (userCertificates.size() == 0) {
            throw new Exception("Issuer not found!");
        }

        UserCertificate matchingCertificate = null;

        for (UserCertificate uc : userCertificates) {
            try (FileInputStream fis = new FileInputStream(uc.getKeystorePath())) {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(fis, uc.getKeystorePassword().toCharArray());

                if (ks.containsAlias(issuerAlias)) {
                    matchingCertificate = uc;
                    break; // našli smo sertifikat, možemo da prekinemo
                }

            } catch (Exception e) {
                System.err.println("Greška pri čitanju keystore-a " + uc.getKeystorePath() + ": " + e.getMessage());
            }
        }

        X509Certificate issuerCert = (X509Certificate) keyStoreReader.readCertificate(
                matchingCertificate.getKeystorePath(),
                matchingCertificate.getKeystorePassword(),
                issuerAlias
        );

        Issuer issuer = keyStoreReader.readIssuerFromStore(
                matchingCertificate.getKeystorePath(),
                issuerAlias,
                matchingCertificate.getKeystorePassword().toCharArray(),
                matchingCertificate.getKeystorePassword().toCharArray()
        );

        // 3) Validnost (primer: danas do +1 godina; prilagodi potrebama)
        Date startDate = new Date();
        Date endDate   = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        // 4) Serijski broj (160-bit random, pozitivan)
        BigInteger serial32 = SerialNumberUtil.generateSerial(32);

        // 2. Generiši sertifikat na osnovu CSR-a
        X509Certificate certificate = caCertificateGenerator.generateEndEntityCertificateFromCsr(
                csr, issuer, issuerCert, startDate, endDate, serial32.toString()
        );

        // 3. Sačuvaj sertifikat na disk
        String cn = extractCN(csr.getSubject());
        if (cn == null || cn.isBlank()) cn = "end-entity";
        String safeFile = cn.replaceAll("[^a-zA-Z0-9._-]", "_");

        Path outDir = Paths.get("src/main/resources/end-entity");
        Files.createDirectories(outDir);

        Path certPath = outDir.resolve(safeFile + "_ee.der");
        writeCertificateDer(certificate, certPath);

        // 4. Ažuriraj bazu
        request.setCertificatePath(certPath.toString());
        request.setStatus("APPROVED");
        csrRepository.save(request);

        CertificateResponse response = new CertificateResponse();
        response.setMessage("End entity uspesno kreiran");

        return response;
    }

    private static String extractCN(X500Name subject) {
        RDN[] rdns = subject.getRDNs(BCStyle.CN);
        if (rdns != null && rdns.length > 0 && rdns[0].getFirst() != null) {
            return ((ASN1String) rdns[0].getFirst().getValue()).getString();
        }
        return null;
    }

    private static void writeCertificateDer(X509Certificate cert, Path path)
            throws IOException, CertificateEncodingException {
        byte[] der = cert.getEncoded(); // ASN.1 DER binary
        Files.write(path, der, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private PKCS10CertificationRequest loadCSR(byte[] raw) throws IOException {
        // Ako je PEM (počinje sa -----BEGIN CERTIFICATE REQUEST-----)
        String s = new String(raw, StandardCharsets.UTF_8).trim();
        if (s.startsWith("-----BEGIN")) {
            try (PEMParser pem = new PEMParser(new StringReader(s))) {
                Object obj = pem.readObject();
                if (obj instanceof PKCS10CertificationRequest) {
                    return (PKCS10CertificationRequest) obj;
                }
                // Neki alati vrate drugačiji wrapper — probaj ručno da izdvojiš Base64
                String base64 = s
                        .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                        .replace("-----END CERTIFICATE REQUEST-----", "")
                        .replaceAll("\\s+", "");
                byte[] der = Base64.getDecoder().decode(base64);
                return new PKCS10CertificationRequest(der);
            }
        }

        // Inače tretiraj kao DER
        return new PKCS10CertificationRequest(raw);
    }


    @Override
    public Long saveCSR(MultipartFile file, Integer userId) throws Exception {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Prazan fajl.");
        }
        // 1) Učitaj bajtove sa upload-a
        byte[] raw = file.getBytes();

        // 2) Parsiraj CSR (radi i za PEM i za DER)
        PKCS10CertificationRequest csr = loadCSR(raw);

        // 3) Proveri potpis CSR-a (da nije korumpiran / nevalidan)
        if (!isCsrSignatureValid(csr)) {
            throw new IllegalArgumentException("CSR potpis nije validan.");
        }

        // 4) Odredi naziv fajla (koristi CN ako postoji, inače originalno ime)
        String cn = extractCN(csr.getSubject());
        String baseName = (cn != null && !cn.isBlank())
                ? cn
                : (file.getOriginalFilename() != null ? file.getOriginalFilename() : "request");
        String safe = sanitize(baseName);

        // 5) Folder i ekstenzija (čuvamo originalni sadržaj; ekstenzija .csr je uobičajena)
        Path dir = Paths.get("src/main/resources/csr");
        Files.createDirectories(dir);
        String ext = guessCsrExtension(file, raw); // .pem ili .csr

        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        Path out = dir.resolve(safe + "_" + ts + ext);

        // 6) Upis na disk
        Files.write(out, raw, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        // 7) Zapiši u bazu
        CsrRequest entity = new CsrRequest();
        entity.setUserId(userId);
        entity.setCsrPath(out.toString());
        entity.setStatus("pending"); // dogovoreno stanje
        // opciono: sačuvaj subject CN/email radi lakšeg pregleda
        // entity.setSubjectCn(cn);

        CsrRequest saved = csrRepository.save(entity);
        return saved.getId();
    }

    /** Provera potpisa CSR-a javnim ključem iz samog CSR-a. */
    private boolean isCsrSignatureValid(PKCS10CertificationRequest csr) throws Exception {
        PublicKey pubKey = new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(pubKey);
        return csr.isSignatureValid(verifier);
    }

    private String guessCsrExtension(MultipartFile file, byte[] raw) {
        String name = file.getOriginalFilename();
        if (name != null && name.toLowerCase().endsWith(".pem")) return ".pem";
        if (name != null && name.toLowerCase().endsWith(".csr")) return ".csr";
        String s = new String(raw, StandardCharsets.UTF_8).trim();
        if (s.startsWith("-----BEGIN")) return ".pem";
        return ".csr";
    }

    /** Sanitizacija naziva fajla. */
    private String sanitize(String input) {
        return input.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

}
