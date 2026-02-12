package com.pki.example.service;

import com.pki.example.data.Password;
import com.pki.example.dto.PasswordDTO;

import java.util.List;

public interface PasswordService {
    Password save(PasswordDTO passwordDTO, Long userId);
    Password findByUserIdAndSite(Long userId, String site);
    List<PasswordDTO> findByUserId(Long userId);
}
