package com.pki.example.controller;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.IntermediateCARequest;
import com.pki.example.service.CAService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/ca")
@RequiredArgsConstructor
public class CAController {

    private final CAService caService;

    @GetMapping
    public ResponseEntity<List<CertificateResponse>> getAllTemplates() {
        List<CertificateResponse> certificates = caService.getAll();
        return ResponseEntity.ok(certificates);
    }

    @PostMapping("/root")
    public ResponseEntity<CertificateResponse> createRootCA(@RequestBody CARequest request) throws Exception {
        CertificateResponse response = caService.createRootCA(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/intermediate")
    public ResponseEntity<CertificateResponse> createIntermediateCA(@RequestBody IntermediateCARequest request) throws Exception {
        CertificateResponse response = caService.createIntermediateCA(request);
        return ResponseEntity.ok(response);
    }
}
