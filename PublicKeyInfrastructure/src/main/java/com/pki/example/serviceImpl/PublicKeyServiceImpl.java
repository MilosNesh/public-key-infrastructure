package com.pki.example.serviceImpl;

import com.pki.example.data.PublicKey;
import com.pki.example.data.User;
import com.pki.example.domain.UserCertificate;
import com.pki.example.repository.PublicKeyRepository;
import com.pki.example.repository.UserCertificateRepository;
import com.pki.example.repository.UserRepository;
import com.pki.example.service.PublicKeyService;
import com.pki.example.util.CertificateUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PublicKeyServiceImpl implements PublicKeyService {
    @Autowired
    private PublicKeyRepository publicKeyRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserCertificateRepository userCertificateRepository;

    @Override
    public PublicKey save(PublicKey publicKey) {
        if(!publicKey.isValid())
            return null;
        PublicKey saved = publicKeyRepository.save(publicKey);
        return saved;
    }

    @Override
    public PublicKey findByUserId(Long userId) {
        PublicKey publicKey = publicKeyRepository.findByUserId(userId);
        return publicKey;
    }

    @Override
    public PublicKey findByUserEmail(String email) {
        User user = userRepository.findByEmail(email);
        PublicKey publicKey = publicKeyRepository.findByUserId(user.getId());
        return publicKey;
    }


    @Override
    public String getByUserEmail(String email) {
        User user = userRepository.findByEmail(email);
        List<UserCertificate> userCertificate = userCertificateRepository.findByUser(user);
        if(userCertificate == null || userCertificate.isEmpty())
            return "";
        try {
            String key = CertificateUtils.getPublicKeyPEM(userCertificate.get(0).getKeystorePath());
            return key;
        } catch (Exception e) {
            return "";
        }
    }


}
