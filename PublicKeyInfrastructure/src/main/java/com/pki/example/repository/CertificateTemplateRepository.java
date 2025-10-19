package com.pki.example.repository;

import com.pki.example.data.CertificateTemplate;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {

}
