package com.pki.example.service;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;

public interface CSRService {
    public CertificateResponse approveCSR(Long csrId, Integer issuerUserId, String issuerAlias) throws Exception;

    Long saveCSR(org.springframework.web.multipart.MultipartFile file, Integer userId) throws Exception;

}
