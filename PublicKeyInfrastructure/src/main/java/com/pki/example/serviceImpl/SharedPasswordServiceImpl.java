package com.pki.example.serviceImpl;

import com.pki.example.data.Password;
import com.pki.example.data.SharedPassword;
import com.pki.example.data.User;
import com.pki.example.dto.PasswordDTO;
import com.pki.example.repository.PasswordRepository;
import com.pki.example.repository.SharedPasswordRepository;
import com.pki.example.repository.UserRepository;
import com.pki.example.service.SharedPasswordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.Date;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class SharedPasswordServiceImpl implements SharedPasswordService {
    @Autowired
    private SharedPasswordRepository sharedPasswordRepository;
    @Autowired
    private PasswordRepository passwordRepository;
    @Autowired
    private UserRepository userRepository;

    @Override
    public SharedPassword save(PasswordDTO passwordDTO, Long ownerId) {
        Password password = passwordRepository.findByUserIdAndSiteName(ownerId, passwordDTO.getSiteName());
        User user = userRepository.findByEmail(passwordDTO.getUsername());
        SharedPassword sharedPassword = new SharedPassword(password.getId(), passwordDTO.getPassword(), user.getId());
        if(!sharedPassword.isValid())
            return null;
        sharedPassword.setCreatedAt(LocalDateTime.now());
        sharedPassword.setCreatedBy(ownerId);
        return sharedPasswordRepository.save(sharedPassword);
    }

    @Override
    public List<PasswordDTO> findAllForUser(Long userId) {
        List<SharedPassword> sharedPasswords = sharedPasswordRepository.findByUserId(userId);
        List<PasswordDTO> passwordDTOs = new ArrayList<>();

        for(SharedPassword sharedPassword : sharedPasswords){
            Password password = passwordRepository.findById(sharedPassword.getPasswordId())
                    .orElseThrow(() -> new RuntimeException("Password not found"));
            PasswordDTO passwordDTO = new PasswordDTO(password.getSiteName(), password.getUsername(), sharedPassword.getPassword());
            passwordDTOs.add(passwordDTO);
        }
        return passwordDTOs;
    }
}
