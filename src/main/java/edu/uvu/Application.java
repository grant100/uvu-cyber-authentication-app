package edu.uvu;

import edu.uvu.cybersecurity.domains.Authority;
import edu.uvu.cybersecurity.domains.Person;
import edu.uvu.cybersecurity.services.PersonRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.lang.reflect.Array;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


@SpringBootApplication
public class Application {

    @Value("${server.port}")
    private Integer port;

    @Value("${server.servlet.contextPath}")
    private String path;

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    // Bootstrap database
    @Bean
    public CommandLineRunner init(PersonRepository repository) {

            return (args)->{
                try{
                    repository.deleteAll();

                    Person test = new Person("test","test", "test","test");
                    ArrayList<Authority> authorities = new ArrayList<>();
                    Collections.addAll(authorities, new Authority("ROLE_DIGEST"), new Authority("ROLE_BASIC"));
                    test.setAuthorities(authorities);
                    repository.saveAndFlush(test);
                    System.out.println("Complete...");
                }catch (DataIntegrityViolationException dve){
                    System.out.println("Skipping DB initialization...");
                    System.out.println("Complete...");
                }

                try{
                    String host = InetAddress.getLocalHost().getHostAddress();
                    String appUrl = String.format("http://%s:%s%s", host, port, path);
                    System.out.println("Application started at "+appUrl);
                }catch (Exception e){
                    // squash
                }

            };
    }
}