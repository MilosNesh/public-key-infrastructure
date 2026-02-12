package com.pki.example.serviceImpl;

import com.pki.example.data.Password;
import com.pki.example.dto.PasswordDTO;
import com.pki.example.repository.PasswordRepository;
import com.pki.example.service.PasswordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class PasswordServiceImpl implements PasswordService {
    @Autowired
    private PasswordRepository passwordRepository;

    @Override
    public Password save(PasswordDTO passwordDTO, Long userId) {
        Password password = new Password(passwordDTO);
        password.setUserId(userId);
        if(!password.isValid())
            return null;
        return passwordRepository.save(password);
    }

    @Override
    public Password findByUserIdAndSite(Long userId, String site) {
        return passwordRepository.findByUserIdAndSiteName(userId, site);
    }

    @Override
    public List<PasswordDTO> findByUserId(Long userId) {
        List<Password> passwords = passwordRepository.findByUserId(userId);
        List<PasswordDTO> passwordDTOS = new ArrayList<>();
        for(Password password : passwords){
            passwordDTOS.add(new PasswordDTO(password));
        }
        return passwordDTOS;
    }
}
