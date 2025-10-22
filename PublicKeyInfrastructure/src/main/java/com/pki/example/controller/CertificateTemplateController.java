package com.pki.example.controller;

import com.pki.example.dto.CertificateTemplateRequestDTO;
import com.pki.example.dto.CertificateTemplateResponseDTO;
import com.pki.example.dto.TemplateDropdownDTO;
import com.pki.example.service.CertificateTemplateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/templates")
@RequiredArgsConstructor
public class CertificateTemplateController {

    private final CertificateTemplateService templateService;

    /**
     * POST /api/templates - Kreira novi Certificate Template
     */
    @PostMapping
    public ResponseEntity<CertificateTemplateResponseDTO> createTemplate(
            @RequestBody CertificateTemplateRequestDTO requestDTO) {
        try {
            CertificateTemplateResponseDTO response = templateService.createTemplate(requestDTO, 1L);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * GET /api/templates/{id} - Vraća template po ID-ju
     */
    @GetMapping("/{id}")
    public ResponseEntity<CertificateTemplateResponseDTO> getTemplateById(@PathVariable Long id) {
        try {
            CertificateTemplateResponseDTO response = templateService.getTemplateById(id);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * GET /api/templates - Vraća sve template-e
     */
    @GetMapping
    public ResponseEntity<List<CertificateTemplateResponseDTO>> getAllTemplates() {
        List<CertificateTemplateResponseDTO> templates = templateService.getAllTemplates();
        return ResponseEntity.ok(templates);
    }

    /**
     * GET /api/templates/active - Vraća sve aktivne template-e
     */
    @GetMapping("/active")
    public ResponseEntity<List<CertificateTemplateResponseDTO>> getActiveTemplates() {
        List<CertificateTemplateResponseDTO> templates = templateService.getActiveTemplates();
        return ResponseEntity.ok(templates);
    }

    /**
     * GET /api/templates/issuer/{issuerAlias} - Vraća template-e po issuer alias-u
     */
    @GetMapping("/issuer/{issuerAlias}")
    public ResponseEntity<List<CertificateTemplateResponseDTO>> getTemplatesByIssuer(
            @PathVariable String issuerAlias) {
        List<CertificateTemplateResponseDTO> templates = templateService.getTemplatesByIssuer(issuerAlias);
        return ResponseEntity.ok(templates);
    }

    /**
     * GET /api/templates/user/{userId}/dropdown - Vraća template-e za dropdown (samo id i label)
     * Vraća aktivne template-e koje pripadaju korisniku
     */
    @GetMapping("/dropdown")
    public ResponseEntity<List<TemplateDropdownDTO>> getTemplatesForUserDropdown() {
        List<TemplateDropdownDTO> templates = templateService.getTemplatesForUserDropdown(1L);
        return ResponseEntity.ok(templates);
    }
}

