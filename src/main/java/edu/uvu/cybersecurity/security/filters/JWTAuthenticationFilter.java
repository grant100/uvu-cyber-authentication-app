package edu.uvu.cybersecurity.security.filters;

import edu.uvu.cybersecurity.security.token.JWTAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTAuthenticationFilter extends OncePerRequestFilter {
    Logger logger = LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader("Authorization");


        if (header == null || header.isEmpty() || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        try {
            logger.debug("Attempting token authentication");
            String jwt = header.replace("Bearer ", "");
            Authentication authRequest = new JWTAuthenticationToken(jwt);

            // delegate to AuthenticationManager to iterate AuthenticationProvider implementation(s)
            Authentication authResults = authenticationManager.authenticate(authRequest);

            // No errors, set Authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authResults);
        } catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();
            logger.debug("Authentication request failed", failed);
        }

        chain.doFilter(request, response);
    }

}
