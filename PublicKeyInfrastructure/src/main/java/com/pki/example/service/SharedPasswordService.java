package com.pki.example.service;

import com.pki.example.data.Password;
import com.pki.example.data.SharedPassword;
import com.pki.example.dto.PasswordDTO;

import java.util.List;

public interface SharedPasswordService {
    public SharedPassword save(PasswordDTO passwordDTO, Long ownerId);
    public List<PasswordDTO> findAllForUser(Long userId);
}
