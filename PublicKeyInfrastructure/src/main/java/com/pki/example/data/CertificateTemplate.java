package com.pki.example.data;

import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "certificate_templates",
        uniqueConstraints = @UniqueConstraint(columnNames = {"name", "issuerAlias"}))
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class CertificateTemplate {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Prikazno ime šablona (npr. "FTN Server Template")
    @Column(nullable = false, length = 128)
    private String name;

    // Alias CA sertifikata koji potpisuje (kako ga već vodiš u svom sistemu/keystore-u)
    @Column(nullable = false, length = 128)
    private String issuerAlias;

    // Regex za CN (može biti null = bez ograničenja)
    @Column(length = 512)
    private String commonNameRegex;

    // Regex za SAN (može biti null = bez ograničenja)
    @Column(length = 512)
    private String sanRegex;

    // Maksimalno trajanje u danima
    @Column(nullable = false)
    private Integer ttlDays;

    // Podrazumevani KeyUsage (skup)
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "template_key_usage", joinColumns = @JoinColumn(name = "template_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "flag", length = 32)
    private Set<KeyUsage> keyUsage;

    // Podrazumevani EKU (skup)
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "template_extended_key_usage", joinColumns = @JoinColumn(name = "template_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "eku", length = 64)
    private Set<ExtendedKeyUsage> extendedKeyUsage;

    @Column(nullable = false)
    private Boolean enabled = true;

    @CreationTimestamp
    private Instant createdAt;

    @UpdateTimestamp
    private Instant updatedAt;
}

