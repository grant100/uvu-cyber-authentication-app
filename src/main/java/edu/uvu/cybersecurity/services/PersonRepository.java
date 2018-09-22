package edu.uvu.cybersecurity.services;

import edu.uvu.cybersecurity.domains.Person;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PersonRepository extends JpaRepository<Person,Long>{
    public Person findByUsername(String username);
}
