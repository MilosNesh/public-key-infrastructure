package com.pki.example.repo;

import com.pki.example.domain.User;
import com.pki.example.domain.UserCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserCertificateRepository extends JpaRepository<UserCertificate, Long> {
    
    List<UserCertificate> findByUser(User user);
    
    List<UserCertificate> findByUserId(Long userId);
    
    Optional<UserCertificate> findByCertificateId(Long certificateId);
    
    List<UserCertificate> findByUserUsername(String username);
    
    boolean existsByCertificateId(Long certificateId);
}


