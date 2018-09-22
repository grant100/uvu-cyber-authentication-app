package edu.uvu.cybersecurity.security;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import edu.uvu.cybersecurity.domains.Person;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Calendar;
import java.util.Date;

public class JWTRepository {

    private static final Logger logger = LoggerFactory.getLogger(JWTRepository.class);

    private String token;
    private String issuer;
    private String secret;
    private Integer timeout;
    private String user;

    public JWTRepository(String issuer, String secret, Integer timeout) {
        this.issuer = issuer;
        this.secret = secret;
        this.timeout = timeout;
        this.user = "uvu-cyber-user";
    }

    public String loadToken() {
        if (isExpired()) {
            logger.debug("Token for user {} is null or expired", user);
            generate();
        }
        logger.debug("Returning cached token");
        return this.token;
    }

    public void erase() {
        this.token = null;
    }


    public boolean isNullOrEmpty() {
        return this.token == null || this.token.isEmpty();
    }

    public boolean isExpired() {
        if (isNullOrEmpty()) {
            return true;
        }

        DecodedJWT decodedJWT = com.auth0.jwt.JWT.decode(this.token);
        return decodedJWT.getExpiresAt().before(new Date());
    }

    public String get() {
        return this.token;
    }

    void generate() {
        try {
            logger.debug("Creating token for subject {}", user);
            Calendar now = Calendar.getInstance();
            long time = now.getTimeInMillis();
            Date expiry = new Date(time + (timeout * 1000));
            Algorithm algorithm = Algorithm.HMAC256(secret);
            this.token = com.auth0.jwt.JWT
                    .create()
                    .withSubject(user)
                    .withIssuer(issuer)
                    .withIssuedAt(new Date())
                    .withExpiresAt(expiry)
                    .sign(algorithm);
        } catch (Exception e) {
            throw e;
        }
        this.user = "uvu-cyber-user";
    }

    public void setUser(String user){
        this.user = user;
    }
}
