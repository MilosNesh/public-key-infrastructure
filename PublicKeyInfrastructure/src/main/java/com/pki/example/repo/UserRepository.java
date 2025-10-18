package com.pki.example.repo;

import com.pki.example.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsername(String username);
    
    Optional<User> findByMail(String mail);
    
    boolean existsByUsername(String username);
    
    boolean existsByMail(String mail);
}


