package com.pki.example.repository;

import com.pki.example.data.PublicKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PublicKeyRepository extends JpaRepository<PublicKey, Long> {
    PublicKey findByUserId(Long userId);
}
