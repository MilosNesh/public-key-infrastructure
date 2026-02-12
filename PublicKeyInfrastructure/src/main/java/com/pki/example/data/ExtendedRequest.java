package com.pki.example.data;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.List;

/**
 * Model koji predstavlja sertifikat sa proširenim poljima koja si naveo.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExtendedRequest implements Serializable {
    // osnovni podaci o issuer-u (alias u sistemu)
    private String issuerAlias;

    // subject fields
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;

    // datum početka i završetka važenja (format JSON: "yyyy-MM-dd")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDate startDate;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private LocalDate endDate;

    // alternativno polje — možeš izračunavati iz start/end ili sačuvati direktno
    private Long ttlDays;

    // serijski broj (kao String da podrži i velike i prefiksirane vrednosti)
    private String serialNumber;

    // ako je CA, maksimalna dozvoljena path length (null ako nije postavljeno)
    private Integer pathLength;
    private Boolean isCA;

    // subjectAltName i email/hostovi
    private List<String> sanList;

    // key usages i extended key usages (ostavljamo stringove radi fleksibilnosti)
    private List<String> keyUsages;
    private List<String> extendedKeyUsages;

    // dodatne ekstenzije
    private List<AdditionalExtension> additionalExtensions;

    // template povezani podaci
    private Long applyTemplateId;
    private Boolean saveAsTemplate;

    // originalni X509 objekt ako želiš da ga zadržiš u memoriji
    private X509Certificate x509Certificate;

    // Opcionalno: možeš dodati polja za issuer CN/organization itd. ako ih želiš direktno tu
    // private Issuer issuer; // ako ti treba kompleksan objekt za issuer

    /**
     * Inner class koja predstavlja dodatnu ekstenziju u JSON-u.
     * Primer:
     * {"name": "Certificate Policies", "value": "1.3.6.1.4.1.11129.2.5.1"}
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AdditionalExtension implements Serializable {
        private String name;
        private String value;
        // opcionalno: dodaj oid, critical flag, rawValue, itd.
        // private String oid;
        // private Boolean critical;
    }
}
