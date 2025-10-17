package com.pki.example.controller;

import com.pki.example.data.CertificateResponse;
import com.pki.example.service.CSRService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/csr")
public class CSRController {

    private final CSRService csrService;

    public CSRController(CSRService csrService) {
        this.csrService = csrService;
    }

//    @PostMapping
//    public ResponseEntity<?> uploadCSR(@RequestParam("file") MultipartFile file, @RequestParam("userId") Long userId) {
//        csrService.saveCSR(file, userId);
//        return ResponseEntity.ok("CSR uploaded successfully.");
//    }

    @PostMapping("/{csrId}/approve")
    public ResponseEntity<CertificateResponse> approveCSR(
            @PathVariable Long csrId,
            @RequestParam("issuerUserId") Long issuerUserId,
            @RequestParam("issuerAlias") String issuerAlias)  throws Exception {
        CertificateResponse response = csrService.approveCSR(csrId, issuerUserId, issuerAlias);
        return ResponseEntity.ok(response);
    }

    }
