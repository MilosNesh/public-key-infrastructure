package com.pki.example.serviceImpl;

import com.pki.example.data.User;
import com.pki.example.repository.UserRepository;
import com.pki.example.security.PasswordHasher;
import com.pki.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public User register(User user) {
        if(!user.isValid())
            return null;
        user.setPassword(PasswordHasher.hashPassword(user.getPassword()));
        return userRepository.save(user);
    }

    public User getByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
