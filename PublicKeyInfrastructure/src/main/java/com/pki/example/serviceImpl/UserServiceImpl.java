package com.pki.example.serviceImpl;

import com.pki.example.data.Role;
import com.pki.example.data.User;
import com.pki.example.dto.LoginDetailsDTO;
import com.pki.example.repository.UserRepository;
import com.pki.example.security.PasswordHasher;
import com.pki.example.service.MailService;
import com.pki.example.service.RoleService;
import com.pki.example.service.UserService;
import com.pki.example.util.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleService roleService;
    @Autowired
    private MailService mailService;
    @Autowired
    private TokenUtils tokenUtils;

    @Override
    public User register(User user) {
        if(!user.isValid())
            return null;
        List<Role> roles = roleService.findByName("ROLE_USER");
        user.setRoles(roles);
        user.setPassword(PasswordHasher.hashPassword(user.getPassword()));
        return userRepository.save(user);
    }

    public User getByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public void setActivationToken(User user, String token) {
        try{
            user.setActivationToken(token);
            userRepository.save(user);
            mailService.sendNotificaitionAsync(user);
        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean activateAccount(String token) {
        User user = userRepository.findByActivationToken(token);

        try {
            if(!tokenUtils.validateToken(token, user)){
                userRepository.delete(user);
                return false;
            }
            if(user == null)
                return false;
            user.setActivationToken(null);
            userRepository.save(user);
            return true;
        } catch (Exception e) {
            userRepository.delete(user);
            return false;
        }

    }

    public boolean login(LoginDetailsDTO loginDetailsDTO) {
        User user = userRepository.findByEmail(loginDetailsDTO.getEmail());
        if(PasswordHasher.verifyPassword(loginDetailsDTO.getPassword(), user.getPassword()))
            return true;
        return false;
    }
}
