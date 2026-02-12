package com.pki.example.serviceImpl;

import com.pki.example.data.CertificateTemplate;
import com.pki.example.dto.CertificateTemplateRequestDTO;
import com.pki.example.dto.CertificateTemplateResponseDTO;
import com.pki.example.dto.TemplateDropdownDTO;
import com.pki.example.repository.CertificateTemplateRepository;
import com.pki.example.service.CertificateTemplateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CertificateTemplateServiceImpl implements CertificateTemplateService {

    @Autowired
    private CertificateTemplateRepository templateRepository;

    @Override
    @Transactional
    public CertificateTemplateResponseDTO createTemplate(CertificateTemplateRequestDTO requestDTO, Long userId) throws Exception {
        // Validacija - provera da li template sa istim imenom i issuer-om već postoji
        if (templateRepository.findByNameAndIssuerAlias(requestDTO.getName(), requestDTO.getIssuerAlias()).isPresent()) {
            throw new IllegalArgumentException("Template sa imenom '" + requestDTO.getName() + 
                "' i issuer alias '" + requestDTO.getIssuerAlias() + "' već postoji.");
        }

        // Validacija osnovnih polja
        if (requestDTO.getName() == null || requestDTO.getName().trim().isEmpty()) {
            throw new IllegalArgumentException("Naziv template-a ne može biti prazan.");
        }

        if (requestDTO.getIssuerAlias() == null || requestDTO.getIssuerAlias().trim().isEmpty()) {
            throw new IllegalArgumentException("Issuer alias ne može biti prazan.");
        }

        if (requestDTO.getTtlDays() == null || requestDTO.getTtlDays() <= 0) {
            throw new IllegalArgumentException("TTL mora biti pozitivan broj.");
        }

        // Kreiranje template-a
        CertificateTemplate template = CertificateTemplate.builder()
                .userId(userId)
                .name(requestDTO.getName())
                .issuerAlias(requestDTO.getIssuerAlias())
                .commonNameRegex(requestDTO.getCommonNameRegex())
                .sanRegex(requestDTO.getSanRegex())
                .ttlDays(requestDTO.getTtlDays())
                .keyUsage(requestDTO.getKeyUsage())
                .extendedKeyUsage(requestDTO.getExtendedKeyUsage())
                .enabled(requestDTO.getEnabled() != null ? requestDTO.getEnabled() : true)
                .build();

        CertificateTemplate saved = templateRepository.save(template);
        
        System.out.println("✓ Kreiran novi Certificate Template: " + saved.getName() + " (ID: " + saved.getId() + ")");
        
        return mapToResponseDTO(saved);
    }

    @Override
    public CertificateTemplateResponseDTO getTemplateById(Long id) throws Exception {
        CertificateTemplate template = templateRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Template sa ID " + id + " ne postoji."));
        
        return mapToResponseDTO(template);
    }

    @Override
    public List<CertificateTemplateResponseDTO> getAllTemplates() {
        return templateRepository.findAll().stream()
                .map(this::mapToResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    public List<CertificateTemplateResponseDTO> getActiveTemplates() {
        return templateRepository.findByEnabled(true).stream()
                .map(this::mapToResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    public List<CertificateTemplateResponseDTO> getTemplatesByIssuer(String issuerAlias) {
        return templateRepository.findByIssuerAlias(issuerAlias).stream()
                .map(this::mapToResponseDTO)
                .collect(Collectors.toList());
    }

    @Override
    public List<TemplateDropdownDTO> getTemplatesForUserDropdown(Long userId) {
        return templateRepository.findByUserId(userId).stream()
                .filter(CertificateTemplate::getEnabled) // Samo aktivni template-i
                .map(template -> new TemplateDropdownDTO(template.getId(), template.getName()))
                .collect(Collectors.toList());
    }

    /**
     * Mapira CertificateTemplate entitet u DTO
     */
    private CertificateTemplateResponseDTO mapToResponseDTO(CertificateTemplate template) {
        return CertificateTemplateResponseDTO.builder()
                .id(template.getId())
                .userId(template.getUserId())
                .name(template.getName())
                .issuerAlias(template.getIssuerAlias())
                .commonNameRegex(template.getCommonNameRegex())
                .sanRegex(template.getSanRegex())
                .ttlDays(template.getTtlDays())
                .keyUsage(template.getKeyUsage())
                .extendedKeyUsage(template.getExtendedKeyUsage())
                .enabled(template.getEnabled())
                .createdAt(template.getCreatedAt())
                .updatedAt(template.getUpdatedAt())
                .build();
    }
}

