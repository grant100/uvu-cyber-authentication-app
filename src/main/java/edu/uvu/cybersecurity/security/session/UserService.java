package edu.uvu.cybersecurity.security.session;

import edu.uvu.cybersecurity.domains.Person;
import edu.uvu.cybersecurity.services.PersonRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {
    private PersonRepository personRepository;

    @Autowired
    public UserService(PersonRepository personRepository){
        this.personRepository = personRepository;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Person person = personRepository.findByUsername(username);
        if(person == null){
            throw new UsernameNotFoundException("Username not found!");
        }

        return new UserPrincipal(person);
    }

    public Person loadByUsername(String username){
        return personRepository.findByUsername(username);
    }
}
