package com.pki.example.service;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.dto.CsrResponseDTO;

import java.util.List;

public interface CSRService {
    public CertificateResponse approveCSR(Long csrId, Long issuerUserId, String issuerAlias) throws Exception;

    Long saveCSR(org.springframework.web.multipart.MultipartFile file, Long userId, String issuerAlias, String startDate, String endDate) throws Exception;

    List<CsrResponseDTO> getCsrsByUserId(Long userId) throws Exception;

}
