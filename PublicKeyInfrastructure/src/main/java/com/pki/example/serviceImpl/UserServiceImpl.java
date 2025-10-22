package com.pki.example.serviceImpl;

import com.pki.example.data.Role;
import com.pki.example.data.User;
import com.pki.example.dto.LoginDetailsDTO;
import com.pki.example.dto.RecoveryDataDTO;
import com.pki.example.repository.UserRepository;
import com.pki.example.security.PasswordGenerator;
import com.pki.example.security.PasswordHasher;
import com.pki.example.service.MailService;
import com.pki.example.service.RoleService;
import com.pki.example.service.UserService;
import com.pki.example.util.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
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
        if(!PasswordGenerator.isPasswordStrongEnough(user.getPassword()))
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

    public boolean resetPassword(RecoveryDataDTO recoveryDataDTO, String token){
        try {
            User user = userRepository.findByEmail(recoveryDataDTO.getEmail());
            if(tokenUtils.validateToken(token, user)){
                user.setPassword(PasswordHasher.hashPassword(recoveryDataDTO.getPassword()));
                user.setMustChangePassword(false);
                userRepository.save(user);
                return true;
            }
            return false;
        }catch (Exception e) {
            return false;
        }
    }

    @Override
    public List<String> getEmails(String email) {
        List<User> users = userRepository.findAll();
        List<String> emails = new ArrayList<>();
        for(User user : users){
            Role role = user.getRoles().get(0);
            if(!user.getEmail().equals(email) && role.getName().equals("ROLE_USER"))
                emails.add(user.getEmail());
        }
        return emails;
    }

    @Override
    public User saveCAUser(User user) {
        String password = PasswordGenerator.generatePassword(12);
        user.setPassword(password);
        if(!user.isValid())
            return null;
        if(!PasswordGenerator.isPasswordStrongEnough(user.getPassword()))
            return null;
        user.setMustChangePassword(true);
        List<Role> roles = roleService.findByName("ROLE_CAUSER");
        user.setRoles(roles);
        user.setPassword(PasswordHasher.hashPassword(user.getPassword()));
        User savedUser = userRepository.save(user);
        if(savedUser != null)
            savedUser.setPassword(password);
        return savedUser;
    }
}
