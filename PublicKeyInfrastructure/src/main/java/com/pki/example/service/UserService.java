package com.pki.example.service;

import com.pki.example.data.User;
import com.pki.example.dto.LoginDetailsDTO;
import com.pki.example.dto.RecoveryDataDTO;

import java.util.List;

public interface UserService {
    User register(User user);
    User getByEmail(String email);
    void setActivationToken(User user, String token);
    boolean activateAccount(String token);
    boolean login(LoginDetailsDTO loginDetailsDTO);
    boolean resetPassword(RecoveryDataDTO recoveryDataDTO, String token);
    List<String> getEmails(String email);
    User saveCAUser(User user);
}
