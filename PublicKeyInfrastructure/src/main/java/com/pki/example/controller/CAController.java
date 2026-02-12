package com.pki.example.controller;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.ExtendedRequest;
import com.pki.example.data.IntermediateCARequest;
import com.pki.example.dto.CAWithValidityDTO;
import com.pki.example.dto.ExtendedCAResponseDTO;
import com.pki.example.service.CertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import com.pki.example.data.User;

import java.util.List;

@RestController
@RequestMapping("/api/ca")
@RequiredArgsConstructor
public class CAController {

    private final CertificateService certificateService;

    @PostMapping("/root")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<ExtendedCAResponseDTO> createRootCA(
            @RequestBody ExtendedRequest request) throws Exception {
        // Koristi NOVI servis (čuva lozinke u bazi)
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        ExtendedCAResponseDTO response = certificateService.createRootCA(request, user.getId());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/intermediate/{issuerUserId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<ExtendedCAResponseDTO> createIntermediateCA(
            @PathVariable Long issuerUserId,
            @RequestBody ExtendedRequest request) throws Exception {

        // Koristi NOVI servis (čuva lozinke u bazi)
        ExtendedCAResponseDTO response = certificateService.createIntermediateCA(request, issuerUserId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/all")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<List<ExtendedCAResponseDTO>> getAll() throws Exception {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<ExtendedCAResponseDTO> allCertificates = certificateService.getAll(user.getId());
        return ResponseEntity.ok(allCertificates);
    }

    @GetMapping("/valid-ca-aliases")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'CAUSER')")
    public ResponseEntity<List<CAWithValidityDTO>> getAllValidCAAliases() throws Exception {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<CAWithValidityDTO> validCAAliases = certificateService.getAllValidCAAliases(user.getId());
        return ResponseEntity.ok(validCAAliases);
    }

    @GetMapping("/end-entity")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'CAUSER')")
    public ResponseEntity<List<ExtendedCAResponseDTO>> getAllEndEntity() throws Exception {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<ExtendedCAResponseDTO> endEntityCertificates = certificateService.getAllEndEntity(user.getId());
        return ResponseEntity.ok(endEntityCertificates);
    }

    @GetMapping("/user/end-entity")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'CAUSER')")
    public ResponseEntity<List<ExtendedCAResponseDTO>> getUserEndEntity() throws Exception {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<ExtendedCAResponseDTO> userEndEntityCertificates = certificateService.getUserEndEntity(user);
        return ResponseEntity.ok(userEndEntityCertificates);
    }
}
