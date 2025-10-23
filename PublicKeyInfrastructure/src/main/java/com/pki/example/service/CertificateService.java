package com.pki.example.service;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.ExtendedRequest;
import com.pki.example.data.IntermediateCARequest;
import com.pki.example.dto.CAWithValidityDTO;
import com.pki.example.dto.ExtendedCAResponseDTO;
import com.pki.example.data.User;

import java.util.List;

public interface CertificateService {
    
    /**
     * Generiše Root CA sertifikat, čuva ga u keystore i lozinku u bazi
     * @param request ExtendedRequest sa svim podacima
     * @return ExtendedCAResponseDTO sa informacijama o kreiranom sertifikatu
     */
    ExtendedCAResponseDTO createRootCA(ExtendedRequest request, Long userId) throws Exception;

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
    List<ExtendedCAResponseDTO> getAll(Long userId) throws Exception;

    /**
     * Vraća sve alias-e CA sertifikata koji mogu da potpisuju druge sertifikate (nisu povučeni)
     * sa njihovim startDate i endDate
     * @return Lista CAWithValidityDTO objekata koji sadrže alias, startDate i endDate
     */
    List<CAWithValidityDTO> getAllValidCAAliases(Long userId) throws Exception;

    /**
     * Vraća sve End Entity sertifikate čitajući DER fajlove iz end-entity foldera
     * @return Lista ExtendedCAResponseDTO objekata koji predstavljaju End Entity sertifikate
     */
    List<ExtendedCAResponseDTO> getAllEndEntity(Long userId) throws Exception;

    /**
     * Vraća sve End Entity sertifikate za određenog korisnika
     * Čita user_certificates tabelu i za svaki red gde je keystore-password null vraća end entity sertifikat iz end-entity foldera
     * @param user Korisnik za koga se traže end entity sertifikati
     * @return Lista ExtendedCAResponseDTO objekata koji predstavljaju End Entity sertifikate za određenog korisnika
     */
    List<ExtendedCAResponseDTO> getUserEndEntity(User user) throws Exception;
}

