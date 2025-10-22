package com.pki.example.controller;

import com.pki.example.data.SessionInfo;
import com.pki.example.data.SessionStore;
import com.pki.example.data.User;
import com.pki.example.dto.LoginDetailsDTO;
import com.pki.example.dto.LoginResponseDTO;
import com.pki.example.dto.RecoveryDataDTO;
import com.pki.example.dto.UserDTO;
import com.pki.example.security.Captcha;
import com.pki.example.service.MailService;
import com.pki.example.service.UserService;
import com.pki.example.util.ClientInfo;
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
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

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
    @Autowired
    private SessionStore sessionStore;
    @Autowired
    private ClientInfo clientInfo;


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
    public ResponseEntity<?> login(
            @RequestBody LoginDetailsDTO authenticationRequest, HttpServletRequest request, HttpServletResponse response) {

        User userByEmail = userService.getByEmail(authenticationRequest.getEmail());
        if (userByEmail == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", "User not found"));
        }
        if (userByEmail.getActivationToken()!=null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", "Account has not been activated"));
        }
        if (!userService.login(authenticationRequest))
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", "Invalid password"));

        boolean captchaOk = captcha.verifyCaptcha(authenticationRequest.getCaptcha());
        if (!captchaOk) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("CAPTCHA failed");
        }
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                authenticationRequest.getEmail(), authenticationRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String sid = UUID.randomUUID().toString();

        String ua = request.getHeader("User-Agent");
        String ip = clientInfo.extractIp(request);
        ClientInfo.ParsedUA parsed = clientInfo.parseUA(ua);

        var now = Instant.now();
        SessionInfo si = SessionInfo.builder()
                .userId(userByEmail.getEmail())
                .sid(sid)
                .ip(ip)
                .userAgent(ua)
                .deviceType(parsed.deviceType())
                .os(parsed.os())
                .browser(parsed.browser())
                .createdAt(now)
                .lastActivityAt(now)
                .revoked(false)
                .expiresAt(null)
                .build();
        sessionStore.save(si);

        String jwt = tokenUtils.generateToken(userByEmail, sid);
        return ResponseEntity.ok(new LoginResponseDTO(jwt, userByEmail.getMustChangePassword()));
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

}
