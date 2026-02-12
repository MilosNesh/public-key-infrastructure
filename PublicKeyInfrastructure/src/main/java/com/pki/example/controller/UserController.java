package com.pki.example.controller;

import com.pki.example.data.User;
import com.pki.example.dto.UserDTO;
import com.pki.example.service.MailService;
import com.pki.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(value = "/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController {
    @Autowired
    private UserService userService;
    @Autowired
    private MailService mailService;

    @GetMapping("/emails")
    @PreAuthorize("hasRole('USER')")
    public List<String> getEmails() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return userService.getEmails(user.getEmail());
    }

    @GetMapping("/organization")
    @PreAuthorize("hasRole('CAUSER')")
    public ResponseEntity<Map<String, String>> getOrganization() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        Map<String, String> response = new HashMap<>();
        response.put("organization", user.getOrganization());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register-ca")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDTO> registerCAUser(@RequestBody UserDTO userDTO) {
        User existUser = userService.getByEmail(userDTO.getEmail());
        if (existUser != null) {
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        }

        User user = userService.saveCAUser(new User(userDTO));
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        try {
            mailService.sendPasswordNotificationAsync(user);
            userDTO.setPassword("");
            return new ResponseEntity<>(userDTO, HttpStatus.CREATED);
        }catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
