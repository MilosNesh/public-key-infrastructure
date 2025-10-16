package com.pki.example.controller;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.IntermediateCARequest;
import com.pki.example.service.CAService;
import com.pki.example.service.CertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/ca")
@RequiredArgsConstructor
@CrossOrigin(origins = "https://localhost:4200")
public class CAController {

    private final CAService caService;
    private final CertificateService certificateService;

    @GetMapping
    public ResponseEntity<List<CertificateResponse>> getAllCertificates() {
        // Koristi stari servis (za kompatibilnost)
        List<CertificateResponse> certificates = caService.getAll();
        return ResponseEntity.ok(certificates);
    }

    @PostMapping("/root")
    public ResponseEntity<CertificateResponse> createRootCA(@RequestBody CARequest request) throws Exception {
        // Koristi NOVI servis (čuva lozinke u bazi)
        //CertificateResponse response = certificateService.createRootCA(request);
        CertificateResponse response = certificateService.createRootCA(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/intermediate")
    public ResponseEntity<CertificateResponse> createIntermediateCA(@RequestBody IntermediateCARequest request) throws Exception {
        // Koristi NOVI servis (čuva lozinke u bazi)
        CertificateResponse response = certificateService.createIntermediateCA(request);
        return ResponseEntity.ok(response);
    }
}
