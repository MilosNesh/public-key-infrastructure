package com.pki.example.controller;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.ExtendedRequest;
import com.pki.example.data.IntermediateCARequest;
import com.pki.example.dto.ExtendedCAResponseDTO;
import com.pki.example.service.CertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/ca")
@RequiredArgsConstructor
public class CAController {

    private final CertificateService certificateService;

    @PostMapping("/root")
    public ResponseEntity<ExtendedCAResponseDTO> createRootCA(
            @RequestBody ExtendedRequest request) throws Exception {
        // Koristi NOVI servis (čuva lozinke u bazi)
        ExtendedCAResponseDTO response = certificateService.createRootCA(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/intermediate/{issuerUserId}")
    public ResponseEntity<ExtendedCAResponseDTO> createIntermediateCA(
            @PathVariable Long issuerUserId,
            @RequestBody ExtendedRequest request) throws Exception {

        // Koristi NOVI servis (čuva lozinke u bazi)
        ExtendedCAResponseDTO response = certificateService.createIntermediateCA(request, issuerUserId);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/all")
    public ResponseEntity<List<ExtendedCAResponseDTO>> getAll() throws Exception {
        List<ExtendedCAResponseDTO> allCertificates = certificateService.getAll();
        return ResponseEntity.ok(allCertificates);
    }
}
