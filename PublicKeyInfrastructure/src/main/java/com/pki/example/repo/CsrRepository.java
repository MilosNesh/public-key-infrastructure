package com.pki.example.repo;

import com.pki.example.domain.CsrRequest;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CsrRepository extends JpaRepository<CsrRequest, Long> {
    
    List<CsrRequest> findByUserId(Long userId);

}
