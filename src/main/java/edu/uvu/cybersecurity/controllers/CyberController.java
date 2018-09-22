package edu.uvu.cybersecurity.controllers;

import com.auth0.jwt.algorithms.Algorithm;
import edu.uvu.cybersecurity.domains.Person;
import edu.uvu.cybersecurity.security.JWTRepository;
import edu.uvu.cybersecurity.services.PersonRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import java.util.*;

@Controller
public class CyberController {
    private PersonRepository personRepository;
    private JWTRepository jwtRepository;

    @Autowired
    public CyberController(PersonRepository personRepository, JWTRepository jwtRepository) {
        this.personRepository = personRepository;
        this.jwtRepository = jwtRepository;
    }

    @RequestMapping("/")
    public ModelAndView landing(){
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("landing.html");
        return modelAndView;
    }

    @ResponseBody
    @RequestMapping("/basic-authentication")
    public String basic() {
        jwtRepository.setUser("jwt");
        String token = jwtRepository.loadToken();
        return "This is secured with Basic Authentication! \r\n\r\nToken: "+token;
    }

    @ResponseBody
    @RequestMapping("/digest-authentication")
    public String digest() {
        jwtRepository.setUser("jwt");
        String token = jwtRepository.loadToken();
        return "This is secured with Digest Authentication!\r\n\r\nToken: "+token;
    }

    @ResponseBody
    @RequestMapping("/token-authentication")
    public String token() {
        return "This is secured with token Authentication!";
    }

    @ResponseBody
    @RequestMapping("/api/persons")
    public List<Person> persons() {
        return personRepository.findAll();
    }

    @RequestMapping("/api/admin")
    public String secured() {
        return "This is a secured area!";
    }


    @RequestMapping("/challenge-one")
    public ModelAndView challengeOne() {
        ModelAndView mav = new ModelAndView();
        mav.addObject("username","username: CYBER");
        mav.addObject("password","password: IT6420");

        mav.setViewName("challenge-one.html");
        return mav;
    }

    // @ResponseBody
    @RequestMapping("/challenge-two")
    public ModelAndView challengeTwo() {
        Person person = personRepository.findByUsername("encoded");
        String tmp = person.getUsername() +":"+person.getPassword();
        String b64 = Base64.getEncoder().encodeToString(tmp.getBytes());
        ModelAndView mav = new ModelAndView();
        mav.addObject("b64",b64);
        mav.setViewName("challenge-two.html");
        return mav;
    }

    @RequestMapping("/challenge-three")
    public ModelAndView challengeThree(HttpServletResponse response) {

        jwtRepository.setUser("spaceman");
        String token = jwtRepository.loadToken();

        Calendar now = Calendar.getInstance();
        long time = now.getTimeInMillis();
        Date expiry = new Date(time + (1800 * 1000));
        Algorithm algorithm = Algorithm.HMAC256("uvu-secret");
        String jwt = com.auth0.jwt.JWT
                .create()
                .withSubject("uvu-cyber-user")
                .withIssuer("uvu-jwt-issuer")
                .withClaim("flag 3",token)
                .withIssuedAt(new Date())
                .withExpiresAt(expiry)
                .sign(algorithm);

        response.setHeader("jwt", jwt);

        ModelAndView mav = new ModelAndView();
        mav.addObject("jwt", jwt);
        mav.setViewName("challenge-three.html");
        return mav;
    }

    @ResponseBody
    @RequestMapping("/challenge-four")
    public List<Person> challengeFour(){
        return personRepository.findAll();
    }

    @ResponseBody
    @RequestMapping("/challenge-five")
    public ModelAndView admin() {
        ModelAndView mav = new ModelAndView();
        mav.setViewName("challenge-five.html");
        return mav;
    }

    @ResponseBody
    @RequestMapping("/digest/error")
    public String digestError() {
        return "digest error!";
    }

    @ResponseBody
    @RequestMapping("/basic/error")
    public String basicError() {
        return "basic error!";
    }

    @ResponseBody
    @RequestMapping("/token/error")
    public String tokenError() {
        return "token error!";
    }
}
