package com.pki.example.security;

import com.pki.example.data.SessionInfo;
import com.pki.example.data.SessionStore;
import com.pki.example.data.User;
import com.pki.example.util.TokenUtils;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private TokenUtils tokenUtils;

    private UserDetailsService userDetailsService;

    protected final Log LOGGER = LogFactory.getLog(getClass());

    private final SessionStore sessionStore;

    public TokenAuthenticationFilter(TokenUtils tokenHelper, UserDetailsService userDetailsService, SessionStore sessionStore) {
        this.tokenUtils = tokenHelper;
        this.userDetailsService = userDetailsService;
        this.sessionStore = sessionStore;
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String email;
        String authToken = tokenUtils.getToken(request);

        try {
            if (authToken != null && SecurityContextHolder.getContext().getAuthentication() == null) { // CHANGED

                email = tokenUtils.getEmailFromToken(authToken);
                String sid = tokenUtils.getSidFromToken(authToken); // NEW

                if (email != null && sid != null) {

                    Optional<SessionInfo> si = sessionStore.find(email, sid);
                    if (si.isEmpty() || si.get().isRevoked()) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session revoked");
                        return;
                    }

                    UserDetails user = userDetailsService.loadUserByUsername(email);
                    if (tokenUtils.validateToken(authToken, (User) user)) {
                        
                        String ua = request.getHeader("User-Agent");
                        String ip = request.getHeader("X-Forwarded-For");
                        if (ip != null && ip.contains(",")) ip = ip.split(",")[0].trim();
                        if (ip == null || ip.isBlank()) ip = request.getRemoteAddr();
                        sessionStore.touch(email, sid, Instant.now(), ip, ua);

                        TokenBasedAuthentication authentication = new TokenBasedAuthentication(user);
                        authentication.setToken(authToken);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        } catch (ExpiredJwtException ex) {
            LOGGER.debug("Token expired!");
        }

        chain.doFilter(request, response);
    }

}

