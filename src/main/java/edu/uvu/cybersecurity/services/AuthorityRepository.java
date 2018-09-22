package edu.uvu.cybersecurity.services;

import edu.uvu.cybersecurity.domains.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<Authority, Long>{
}
