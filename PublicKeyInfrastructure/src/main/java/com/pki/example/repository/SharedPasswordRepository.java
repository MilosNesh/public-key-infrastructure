package com.pki.example.repository;

import com.pki.example.data.SharedPassword;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SharedPasswordRepository extends JpaRepository<SharedPassword, Long> {
    List<SharedPassword> findByUserId(Long userId);
}
