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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


@SpringBootApplication
public class Application {

    @Value("${uvu.security.username}")
    private String username;

    @Value("${uvu.security.password}")
    private String password;

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

                    System.out.println("Initializing DB...");
                    Person one = new Person("one","one", password,username);
                    ArrayList<Authority> authorities = new ArrayList<>();
                    Collections.addAll(authorities,new Authority("ROLE_ONE"));
                    one.setAuthorities(authorities);
                    repository.save(one);

                    Person three = new Person("three","three", "b64","encoded");
                    authorities.clear();
                    Collections.addAll(authorities,new Authority("ROLE_THREE"));
                    three.setAuthorities(authorities);
                    repository.save(three);

                    Person two = new Person("two","two", "IT6420","CYBER");
                    authorities.clear();
                    Collections.addAll(authorities, new Authority("ROLE_TWO"));
                    two.setAuthorities(authorities);
                    repository.save(two);

                    Person four = new Person("elon","musk", "spacex","spaceman");
                    authorities.clear();
                    Collections.addAll(authorities, new Authority("ROLE_FOUR"));
                    four.setAuthorities(authorities);
                    repository.save(four);

                    Person five = new Person("ADMINISTRATOR","ADMINISTRATOR", "3j9bn2-vdjz5%9!==","SUPER_ADMIN");
                    authorities.clear();
                    Collections.addAll(authorities, new Authority("ROLE_FIVE"), new Authority("ROLE_SUPER_ADMIN"));
                    five.setAuthorities(authorities);
                    five.setDetail("flag 4: /challenge-five (use basic auth)");
                    repository.save(five);

                    Person six = new Person("six","six", "token","jwt");
                    authorities.clear();
                    Collections.addAll(authorities, new Authority("ROLE_TOKEN"));
                    six.setAuthorities(authorities);
                    repository.save(six);


                    Person test = new Person("test","test", "test","test");
                    authorities.clear();
                    Collections.addAll(authorities, new Authority("ROLE_DIGEST"), new Authority("ROLE_BASIC"));
                    test.setAuthorities(authorities);
                    repository.save(test);

                    repository.flush();
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