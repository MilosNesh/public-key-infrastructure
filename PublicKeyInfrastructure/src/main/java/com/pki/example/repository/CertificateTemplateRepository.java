package com.pki.example.repository;

import com.pki.example.data.CertificateTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {
    
    Optional<CertificateTemplate> findByNameAndIssuerAlias(String name, String issuerAlias);
    
    List<CertificateTemplate> findByEnabled(Boolean enabled);
    
    List<CertificateTemplate> findByIssuerAlias(String issuerAlias);
    
    List<CertificateTemplate> findByUserId(Long userId);
    
    List<CertificateTemplate> findByUserIdAndEnabled(Long userId, Boolean enabled);
}
