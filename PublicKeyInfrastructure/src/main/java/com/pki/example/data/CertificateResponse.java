package com.pki.example.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CertificateResponse {
    private String alias;                // alias u keystore-u
    private String subjectDN;            // Distinguished Name
    private String issuerDN;
    private String serialNumber;
    private Date notBefore;
    private Date notAfter;
           // Base64 encoded sertifikat
    private String message;
}
