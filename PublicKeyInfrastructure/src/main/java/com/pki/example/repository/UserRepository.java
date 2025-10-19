package com.pki.example.repository;

import com.pki.example.data.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    User findByEmail(String email);
    User findByActivationToken(String activationToken);
}
