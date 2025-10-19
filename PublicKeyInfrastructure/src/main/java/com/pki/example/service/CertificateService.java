package com.pki.example.service;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.IntermediateCARequest;

import java.util.List;

public interface CertificateService {
    
    /**
     * Generiše Root CA sertifikat, čuva ga u keystore i lozinku u bazi
     * @param request CARequest sa svim podacima
     * @return CertificateResponse sa informacijama o kreiranom sertifikatu
     */
    CertificateResponse createRootCA(CARequest request) throws Exception;

    /**
     * Generiše Intermediate CA sertifikat, čuva ga u keystore i lozinku u bazi
     * @param request IntermediateCARequest sa svim podacima
     * @return CertificateResponse sa informacijama o kreiranom sertifikatu
     */
    CertificateResponse createIntermediateCA(IntermediateCARequest request, Long issuerUserId) throws Exception;

    /**
     * Vraća sve sertifikate (root, intermediate, end-entity) iz user_certificates tabele
     * @return Lista CertificateResponse objekata koji predstavljaju sve sertifikate bez duplikata
     */
    List<CertificateResponse> getAll() throws Exception;
}

