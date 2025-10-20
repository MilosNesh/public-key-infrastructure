package com.pki.example.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class ExtendedCAResponse {
    private String alias;                // alias u keystore-u / identifikator
    private String issuerAlias;          // alias izdavaoca u sistemu

    // DN i izdvojena subject polja (korisno za UI)
    private String subjectDN;            // Distinguished Name (kompletan)
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;

    private String issuerDN;             // Distinguished Name izdavaoca

    // serijski i validnost
    private String serialNumber;
    private Date notBefore;
    private Date notAfter;
    private Long ttlDays;                // opcionalno

    // CA info
    private Boolean isCA;
    private Integer pathLength;

    // SAN, key usages i ekstenzije
    private List<String> sanList;
    private List<String> keyUsages;
    private List<String> extendedKeyUsages;
    private List<ExtendedRequest.AdditionalExtension> additionalExtensions;

    // PEM / DER i lanac
    private String certificatePEM;            // Base64 PEM (-----BEGIN CERTIFICATE-----...)

    // Public key i signature info
    private String publicKeyAlgorithm;
    private Integer publicKeySize;           // npr. 2048, 3072, 4096, ili null za EC
    private String signatureAlgorithm;

    // opcionalno: poruka ili upozorenja prilikom izdavanja
    private String message;
}
