package com.pki.example.repo;

import com.pki.example.domain.CsrRequest;
import com.pki.example.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CsrRepository extends JpaRepository<CsrRequest, Long> {

}
