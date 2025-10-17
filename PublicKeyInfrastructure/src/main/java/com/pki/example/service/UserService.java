package com.pki.example.service;

import com.pki.example.data.User;
import com.pki.example.dto.LoginDetailsDTO;

public interface UserService {
    User register(User user);
    User getByEmail(String email);
    void setActivationToken(User user, String token);
    boolean activateAccount(String token);
    boolean login(LoginDetailsDTO loginDetailsDTO);
}
