package com.pki.example.service;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.ExtendedRequest;
import com.pki.example.data.IntermediateCARequest;
import com.pki.example.dto.CAWithValidityDTO;
import com.pki.example.dto.ExtendedCAResponseDTO;

import java.util.List;

public interface CertificateService {
    
    /**
     * Generiše Root CA sertifikat, čuva ga u keystore i lozinku u bazi
     * @param request ExtendedRequest sa svim podacima
     * @return ExtendedCAResponseDTO sa informacijama o kreiranom sertifikatu
     */
    ExtendedCAResponseDTO createRootCA(ExtendedRequest request) throws Exception;

    /**
     * Generiše Intermediate CA sertifikat, čuva ga u keystore i lozinku u bazi
     * @param request ExtendedRequest sa svim podacima
     * @return ExtendedCAResponseDTO sa informacijama o kreiranom sertifikatu
     */
    ExtendedCAResponseDTO createIntermediateCA(ExtendedRequest request, Long issuerUserId) throws Exception;

    /**
     * Vraća sve sertifikate (root, intermediate, end-entity) iz user_certificates tabele
     * @return Lista ExtendedCAResponseDTO objekata koji predstavljaju sve sertifikate bez duplikata
     */
    List<ExtendedCAResponseDTO> getAll() throws Exception;

    /**
     * Vraća sve alias-e CA sertifikata koji mogu da potpisuju druge sertifikate (nisu povučeni)
     * sa njihovim startDate i endDate
     * @return Lista CAWithValidityDTO objekata koji sadrže alias, startDate i endDate
     */
//    List<CAWithValidityDTO> getAllValidCAAliases() throws Exception;

    /**
     * Vraća sve End Entity sertifikate čitajući DER fajlove iz end-entity foldera
     * @return Lista ExtendedCAResponseDTO objekata koji predstavljaju End Entity sertifikate
     */
    List<ExtendedCAResponseDTO> getAllEndEntity() throws Exception;
}

