package com.pki.example.service;

import com.pki.example.dto.CertificateTemplateRequestDTO;
import com.pki.example.dto.CertificateTemplateResponseDTO;
import com.pki.example.dto.TemplateDropdownDTO;

import java.util.List;

public interface CertificateTemplateService {
    
    /**
     * Kreira novi Certificate Template
     * @param requestDTO podaci za kreiranje template-a
     * @return kreirani template
     */
    CertificateTemplateResponseDTO createTemplate(CertificateTemplateRequestDTO requestDTO, Long userId) throws Exception;
    
    /**
     * Vraća template po ID-ju
     * @param id ID template-a
     * @return template ili exception ako ne postoji
     */
    CertificateTemplateResponseDTO getTemplateById(Long id) throws Exception;
    
    /**
     * Vraća sve template-e
     * @return lista svih template-a
     */
    List<CertificateTemplateResponseDTO> getAllTemplates();
    
    /**
     * Vraća sve aktivne template-e
     * @return lista aktivnih template-a
     */
    List<CertificateTemplateResponseDTO> getActiveTemplates();
    
    /**
     * Vraća template-e za određeni issuerAlias
     * @param issuerAlias alias CA sertifikata
     * @return lista template-a
     */
    List<CertificateTemplateResponseDTO> getTemplatesByIssuer(String issuerAlias);
    
    /**
     * Vraća template-e za dropdown (samo id i label) za određenog korisnika
     * @param userId ID korisnika
     * @return lista template-a sa id i label za dropdown
     */
    List<TemplateDropdownDTO> getTemplatesForUserDropdown(Long userId);
}

