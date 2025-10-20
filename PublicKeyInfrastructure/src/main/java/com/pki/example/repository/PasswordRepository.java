package com.pki.example.repository;

import com.pki.example.data.Password;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PasswordRepository extends JpaRepository<Password, Long> {
    public Password findByUserIdAndSiteName(Long userId, String siteName);
    public List<Password> findByUserId(Long userId);
}
