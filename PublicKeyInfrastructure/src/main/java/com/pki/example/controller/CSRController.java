package com.pki.example.controller;

import com.pki.example.data.CertificateResponse;
import com.pki.example.data.User;
import com.pki.example.dto.CsrResponseDTO;
import com.pki.example.dto.CsrUploadResponse;
import com.pki.example.service.CSRService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/csr")
public class CSRController {

    private final CSRService csrService;

    public CSRController(CSRService csrService) {
        this.csrService = csrService;
    }

    @PostMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> uploadCSR(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "issuerAlias", required = false) String issuerAlias,
            @RequestParam(value = "startDate", required = false) String startDate,
            @RequestParam(value = "endDate", required = false) String endDate) throws Exception {
        Long savedId = csrService.saveCSR(file, 1L, issuerAlias, startDate, endDate);
        CsrUploadResponse body = new CsrUploadResponse(
                "OK",
                savedId,
                file.getOriginalFilename(),
                file.getSize()
        );
        return ResponseEntity.ok(body);
    }

    @PostMapping("/{csrId}/approve")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<CertificateResponse> approveCSR(
            @PathVariable Long csrId,
            @RequestParam("issuerAlias") String issuerAlias)  throws Exception {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        CertificateResponse response = csrService.approveCSR(csrId, user.getId());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<CsrResponseDTO>> getCsrsByUserId() throws Exception {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        List<CsrResponseDTO> csrList = csrService.getCsrsByUserId(user.getId());
        return ResponseEntity.ok(csrList);
    }

    @GetMapping("/all")
    @PreAuthorize("hasAnyRole('ADMIN', 'CAUSER')")
    public ResponseEntity<List<CsrResponseDTO>> getAllCsrs() throws Exception {
        List<CsrResponseDTO> csrList = csrService.getAllCsrs();
        return ResponseEntity.ok(csrList);
    }

}
