package com.pki.example.controller;

import com.pki.example.data.User;
import com.pki.example.dto.UserDTO;
import com.pki.example.service.UserService;
import com.pki.example.util.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {
    @Autowired
    private UserService userService;
    @Autowired
    private TokenUtils tokenUtils;

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
        String token = tokenUtils.generateToken(user);
        userService.setActivationToken(user, token);
        userDTO.setPassword("");
        return new ResponseEntity<>(userDTO, HttpStatus.CREATED);
    }

    @GetMapping("/activate")
    public ResponseEntity<String> activateAccount(@RequestParam("token") String token) {
        boolean activated = this.userService.activateAccount(token);

        String htmlResponse;

        if (activated) {
            htmlResponse = "<html> <head><title>Activation Success</title></head>" +
            "<body style='font-family: Arial; text-align: center; margin-top: 50px;'>" +
                "<h2 style='color: green;'>✅ Your account has been successfully activated!</h2>" +
                "<p>You can now <a href='/login'>log in</a>.</p>" +
            "</body> </html>";
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .body(htmlResponse);
        } else {
            htmlResponse = "<html>" +
            "<head><title>Activation Failed</title></head>" +
            "<body style='font-family: Arial; text-align: center; margin-top: 50px;'>" +
                "<h2 style='color: red;'>❌ Invalid or expired token!</h2>" +
                "<p>Please check your activation link or contact support.</p>" +
            "</body> </html>";

            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .contentType(MediaType.TEXT_HTML)
                    .body(htmlResponse);
        }
    }

}
