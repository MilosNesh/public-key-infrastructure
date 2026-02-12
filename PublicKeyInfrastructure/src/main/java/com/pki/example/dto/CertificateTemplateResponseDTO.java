package com.pki.example.dto;

import com.pki.example.data.ExtendedKeyUsage;
import com.pki.example.data.KeyUsage;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertificateTemplateResponseDTO {
    private Long id;
    private Long userId;
    private String name;
    private String issuerAlias;
    private String commonNameRegex;
    private String sanRegex;
    private Integer ttlDays;
    private Set<KeyUsage> keyUsage;
    private Set<ExtendedKeyUsage> extendedKeyUsage;
    private Boolean enabled;
    private Instant createdAt;
    private Instant updatedAt;
}

