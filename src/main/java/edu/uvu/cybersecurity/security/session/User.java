package edu.uvu.cybersecurity.security.session;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

public class User  extends AbstractAuthenticationToken{

    UserPrincipal principal;
    public User(UserPrincipal principal){
        super(principal.getAuthorities());
        this.principal = principal;
    }
    public User(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
    }

    @Override
    public Object getCredentials() {
        return principal.getPassword();
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }
}
