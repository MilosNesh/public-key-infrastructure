package com.pki.example.controller;

import com.pki.example.data.User;
import com.pki.example.dto.UserDTO;
import com.pki.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.MediaType;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {
    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserDTO> registration(@RequestBody UserDTO userDTO) {
        User existUser = userService.getByEmail(userDTO.getEmail());
        if (existUser != null) {
//            throw new ResourceConflictException(existUser.getId(), "Username already exists");
        }

        User user = userService.register(new User(userDTO));
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(userDTO, HttpStatus.CREATED);
    }
}
