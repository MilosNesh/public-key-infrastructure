package com.pki.example.controller;

import com.pki.example.data.SessionInfo;
import com.pki.example.data.SessionStore;
import com.pki.example.dto.SessionDTO;
import com.pki.example.util.TokenUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/sessions")
@RequiredArgsConstructor
public class SessionController {

    private final SessionStore sessions;
    private final TokenUtils tokenUtils;

    @GetMapping
    public List<SessionDTO> list(Authentication auth) {
        String userId = auth.getName();
        return sessions.findAllByUser(userId).stream()
                .filter(s -> !s.isRevoked())
                .sorted(Comparator.comparing(SessionInfo::getLastActivityAt).reversed())
                .map(SessionDTO::from)
                .collect(Collectors.toList());
    }


    @DeleteMapping("/{sid}")
    public void revoke(@PathVariable String sid, Authentication auth) {
        sessions.revoke(auth.getName(), sid);
    }

    @PostMapping("/revoke-all-except-current")
    public void revokeOthers(@RequestHeader("Authorization") String authz, Authentication auth) {
        String bearer = (authz != null && authz.startsWith("Bearer ")) ? authz.substring(7) : null;
        String currentSid = null;

        if (bearer != null) {
            currentSid = tokenUtils.getSidFromToken(bearer);
        }

        for (SessionInfo s : sessions.findAllByUser(auth.getName())) {
            if (currentSid == null || !s.getSid().equals(currentSid)) {
                sessions.revoke(auth.getName(), s.getSid());
            }
        }
    }
}
