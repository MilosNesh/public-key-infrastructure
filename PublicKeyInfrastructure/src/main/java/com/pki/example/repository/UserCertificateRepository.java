package com.pki.example.repository;

import com.pki.example.data.User;
import com.pki.example.domain.UserCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserCertificateRepository extends JpaRepository<UserCertificate, Integer> {
    
    List<UserCertificate> findByUser(User user);
    
    List<UserCertificate> findByUserId(Long userId);
    
    Optional<UserCertificate> findByCertificateId(Integer certificateId);

    boolean existsByCertificateId(Long certificateId);
}


