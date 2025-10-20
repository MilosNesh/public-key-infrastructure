package com.pki.example.service;

import com.pki.example.data.PublicKey;

public interface PublicKeyService {
    PublicKey save(PublicKey publicKey);
    PublicKey findByUserId(Long userId);
}
