package edu.uvu.cybersecurity.security.providers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import edu.uvu.cybersecurity.domains.Person;
import edu.uvu.cybersecurity.security.session.User;
import edu.uvu.cybersecurity.security.session.UserPrincipal;
import edu.uvu.cybersecurity.security.session.UserService;
import edu.uvu.cybersecurity.security.token.JWTAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;


public class JWTAuthProvider implements AuthenticationProvider{

    Logger logger = LoggerFactory.getLogger(JWTAuthProvider.class);

    private UserService userDetailsService;

    public JWTAuthProvider(UserService userDetailService){
        this.userDetailsService = userDetailService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try{

            String jwt = ((JWTAuthenticationToken) authentication).getToken();
            DecodedJWT decodedJWT = JWT.decode(jwt);

            logger.debug("Verifying token with subject {}", decodedJWT.getSubject());
            Algorithm algorithm = Algorithm.HMAC256("this-is-a-secret");
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("uvu-cyber-security")
                    .withSubject(decodedJWT.getSubject())
                    .build();

            verifier.verify(jwt);

            Person person = userDetailsService.loadByUsername(decodedJWT.getSubject());
            UserPrincipal principal = new UserPrincipal(person);
            return new User(principal);
        }catch(JWTVerificationException e){
            throw new BadCredentialsException("Invalid token");
        }catch(Exception e){
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JWTAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
