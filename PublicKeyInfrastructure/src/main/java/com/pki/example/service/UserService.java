package com.pki.example.service;

import com.pki.example.data.User;

public interface UserService {
    User register(User user);
    User getByEmail(String email);
}
