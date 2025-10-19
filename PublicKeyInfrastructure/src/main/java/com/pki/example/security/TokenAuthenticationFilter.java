package com.pki.example.security;

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

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private TokenUtils tokenUtils;

    private UserDetailsService userDetailsService;

    protected final Log LOGGER = LogFactory.getLog(getClass());

    public TokenAuthenticationFilter(TokenUtils tokenHelper, UserDetailsService userDetailsService) {
        this.tokenUtils = tokenHelper;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {


        String email;

        // 1. Preuzimanje JWT tokena iz zahteva
        String authToken = tokenUtils.getToken(request);

        try {

            if (authToken != null) {

                // 2. Citanje emaila iz tokena
                email = tokenUtils.getEmailFromToken(authToken);

                if (email != null) {

                    // 3. Preuzimanje korisnika na osnovu username-a
                    UserDetails user = userDetailsService.loadUserByUsername(email);
                    // 4. Provera da li je prosledjeni token validan
                    if (tokenUtils.validateToken(authToken, (User) user)) {

                        // 5. Kreiraj autentifikaciju
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

