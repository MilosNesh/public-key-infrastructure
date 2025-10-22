package com.pki.example.controller;

import com.pki.example.data.User;
import com.pki.example.dto.LoginDetailsDTO;
import com.pki.example.dto.RecoveryDataDTO;
import com.pki.example.dto.UserDTO;
import com.pki.example.security.Captcha;
import com.pki.example.service.MailService;
import com.pki.example.service.UserService;
import com.pki.example.util.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {
    @Autowired
    private UserService userService;
    @Autowired
    private TokenUtils tokenUtils;
    @Autowired
    private Captcha captcha;
    @Autowired
    private MailService mailService;
    @Autowired
    private AuthenticationManager authenticationManager;


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
        String token = tokenUtils.generateActivationAndResetToken(user, 1000*60*5);
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
                "<h2 style='color: green;'> Your account has been successfully activated!</h2>" +
                "<p>You can now <a href='https://localhost:4200/login'>Sign in</a>.</p>" +
            "</body> </html>";
            return ResponseEntity.ok()
                    .contentType(MediaType.TEXT_HTML)
                    .body(htmlResponse);
        } else {
            htmlResponse = "<html>" +
            "<head><title>Activation Failed</title></head>" +
            "<body style='font-family: Arial; text-align: center; margin-top: 50px;'>" +
                "<h2 style='color: red;'> Invalid or expired token!</h2>" +
                "<p>Please check your activation link or contact support.</p>" +
            "</body> </html>";

            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .contentType(MediaType.TEXT_HTML)
                    .body(htmlResponse);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(
            @RequestBody LoginDetailsDTO authenticationRequest, HttpServletResponse response) {

        User userByEmail = userService.getByEmail(authenticationRequest.getEmail());
        if (userByEmail == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
        if (userByEmail.getActivationToken()!=null) {
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body("Account has not been activated");
        }
        if (!userService.login(authenticationRequest))
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid email or password");

        boolean captchaOk = captcha.verifyCaptcha(authenticationRequest.getCaptcha());
        if (!captchaOk) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("CAPTCHA failed");
        }
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                authenticationRequest.getEmail(), authenticationRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();
        String jwt = tokenUtils.generateToken(userByEmail);
//        int expiresIn = tokenUtils.getExpiredIn();

        // Vrati token kao odgovor na uspesnu autentifikaciju
        return ResponseEntity.ok(jwt);
    }

    @PostMapping("/recoverylink")
    public ResponseEntity<String> sendRecoveryLink(@RequestBody String email) {
        User userByEmail = userService.getByEmail(email);
        if (userByEmail == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
        try {
            mailService.sendRecoverNotificationAsync(userByEmail);
        }catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
        return ResponseEntity.ok("");
    }

    @PostMapping("/recover")
    public ResponseEntity<String> recover(@RequestBody RecoveryDataDTO recoveryDataDTO, HttpServletRequest request) {
        boolean isReset = userService.resetPassword(recoveryDataDTO, tokenUtils.getToken(request));
        if(!isReset)
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("You do not have permission to reset password.");
        return ResponseEntity.ok("");
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Radi");
    }

    @GetMapping("/test2")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> test2() {
        return ResponseEntity.ok("Radi admin");
    }

}
