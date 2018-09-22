package edu.uvu.cybersecurity.security.providers;

import edu.uvu.cybersecurity.domains.Person;
import edu.uvu.cybersecurity.security.session.User;
import edu.uvu.cybersecurity.security.session.UserPrincipal;
import edu.uvu.cybersecurity.security.session.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class BasicAuthProvider implements AuthenticationProvider {
    Logger logger = LoggerFactory.getLogger(BasicAuthProvider.class);

    private UserService userDetailsService;

    public BasicAuthProvider(UserService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        try {
            logger.debug("Verifying credentials for user {}", authentication.getName());
            String credentials = authentication.getCredentials().toString();
            Person person = userDetailsService.loadByUsername(authentication.getName());
            if (person == null) {
                throw new UsernameNotFoundException("No username found");
            }

            if (!person.getPassword().equals(credentials)) {
                throw new BadCredentialsException("Invalid credentials");
            }
            UserPrincipal principal = new UserPrincipal(person);

            logger.debug("Creating system user user {}", principal.getPerson().getUsername());
            return new User(principal);
        } catch (UsernameNotFoundException unfe) {
            throw unfe;
        } catch (BadCredentialsException bce) {
            throw bce;
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
