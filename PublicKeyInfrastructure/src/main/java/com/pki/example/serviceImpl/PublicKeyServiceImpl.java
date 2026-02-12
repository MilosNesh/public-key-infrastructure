package com.pki.example.serviceImpl;

import com.pki.example.data.PublicKey;
import com.pki.example.data.User;
import com.pki.example.repository.PublicKeyRepository;
import com.pki.example.repository.UserRepository;
import com.pki.example.service.PublicKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PublicKeyServiceImpl implements PublicKeyService {
    @Autowired
    private PublicKeyRepository publicKeyRepository;
    @Autowired
    private UserRepository userRepository;
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
}
