package com.pki.example.dto;

import com.pki.example.data.ExtendedKeyUsage;
import com.pki.example.data.KeyUsage;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateTemplateRequestDTO {
    private String name;
    private String issuerAlias;
    private String commonNameRegex;
    private String sanRegex;
    private Integer ttlDays;
    private Set<KeyUsage> keyUsage;
    private Set<ExtendedKeyUsage> extendedKeyUsage;
    private Boolean enabled;
}

