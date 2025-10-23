package com.pki.example.controller;

import com.pki.example.dto.CertificateTemplateRequestDTO;
import com.pki.example.dto.CertificateTemplateResponseDTO;
import com.pki.example.dto.TemplateDropdownDTO;
import com.pki.example.service.CertificateTemplateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/templates")
@RequiredArgsConstructor
public class CertificateTemplateController {

    private final CertificateTemplateService templateService;


    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
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

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
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

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<List<CertificateTemplateResponseDTO>> getAllTemplates() {
        List<CertificateTemplateResponseDTO> templates = templateService.getAllTemplates();
        return ResponseEntity.ok(templates);
    }


    @GetMapping("/active")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<List<CertificateTemplateResponseDTO>> getActiveTemplates() {
        List<CertificateTemplateResponseDTO> templates = templateService.getActiveTemplates();
        return ResponseEntity.ok(templates);
    }


    @GetMapping("/issuer/{issuerAlias}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<List<CertificateTemplateResponseDTO>> getTemplatesByIssuer(
            @PathVariable String issuerAlias) {
        List<CertificateTemplateResponseDTO> templates = templateService.getTemplatesByIssuer(issuerAlias);
        return ResponseEntity.ok(templates);
    }

    @GetMapping("/dropdown")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<List<TemplateDropdownDTO>> getTemplatesForUserDropdown() {
        List<TemplateDropdownDTO> templates = templateService.getTemplatesForUserDropdown(1L);
        return ResponseEntity.ok(templates);
    }
}

