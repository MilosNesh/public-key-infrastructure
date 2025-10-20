package com.pki.example.controller;

import com.pki.example.data.Password;
import com.pki.example.data.PublicKey;
import com.pki.example.data.User;
import com.pki.example.dto.PasswordDTO;
import com.pki.example.service.PasswordService;
import com.pki.example.service.PublicKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(value = "/password", produces = MediaType.APPLICATION_JSON_VALUE)
public class PasswordController {
    @Autowired
    private PasswordService passwordService;
    @Autowired
    private PublicKeyService publicKeyService;

    @PostMapping("/save-password")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<PasswordDTO> savePassword(@RequestBody PasswordDTO passwordDTO) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        Password password =  passwordService.save(passwordDTO, user.getId());
        if(password == null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        return ResponseEntity.ok(passwordDTO);
    }

    @GetMapping("/password-for-site/{site}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<PasswordDTO> getForSite(@PathVariable String site) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Password password = passwordService.findByUserIdAndSite(user.getId(), site);
        if(password == null)
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        PasswordDTO passwordDTO = new PasswordDTO(password);
        return ResponseEntity.ok(passwordDTO);
    }

    @GetMapping("/for-user")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<PasswordDTO>> getAllForUser() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseEntity.ok(passwordService.findByUserId(user.getId()));
    }

    @PostMapping("/save-key")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> savePublicKey(@RequestBody String publicKeyPem) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(user == null)
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        PublicKey publicKey = new PublicKey(user.getId(), publicKeyPem);
        PublicKey saved =  publicKeyService.save(publicKey);
        if(saved == null)
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        return ResponseEntity.ok(saved.getKey());
    }

    @GetMapping("/load-key")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> getPublicKey() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(user == null)
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        PublicKey publicKey =  publicKeyService.findByUserId(user.getId());
        if(publicKey == null)
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        return ResponseEntity.ok(publicKey.getKey());
    }
}
