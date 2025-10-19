package com.pki.example.repo;

import com.pki.example.domain.CsrRequest;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CsrRepository extends JpaRepository<CsrRequest, Long> {

}
