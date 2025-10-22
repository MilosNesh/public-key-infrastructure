package com.pki.example.repository;

import com.pki.example.data.CaSecret;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CaSecretRepository extends JpaRepository<CaSecret, Long> {
    Optional<CaSecret> findByCaUserId(Long caUserId);
}
