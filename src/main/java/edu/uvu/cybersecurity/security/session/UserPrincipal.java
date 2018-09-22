package edu.uvu.cybersecurity.security.session;

import edu.uvu.cybersecurity.domains.Authority;
import edu.uvu.cybersecurity.domains.Person;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserPrincipal implements UserDetails {
    private Person person;

    private List<SimpleGrantedAuthority> authorities = new ArrayList<>();

    public UserPrincipal(Person person){
        this.person = person;
        setAuthorities();
    }

    public Person getPerson(){
        return this.person;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return person.getPassword();
    }

    @Override
    public String getUsername() {
        return person.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


    private void setAuthorities(){
        for(Authority authority : person.getAuthorities()){
            SimpleGrantedAuthority role = new SimpleGrantedAuthority(authority.getRole());
            authorities.add(role);
        }
    }
}
