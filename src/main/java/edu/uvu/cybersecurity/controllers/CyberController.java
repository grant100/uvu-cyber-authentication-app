package edu.uvu.cybersecurity.controllers;

import edu.uvu.cybersecurity.model.UserData;
import edu.uvu.cybersecurity.security.JWTRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;


@Controller
public class CyberController {
    Logger logger = LoggerFactory.getLogger(CyberController.class);
    private JWTRepository jwtRepository;

    @Value("${api.base}")
    private String base;

    @Value("${api.port}")
    private String port;

    @Value("${api.context}")
    private String context;

    @Value("${api.path}")
    private String path;

    RestTemplate restTemplate = new RestTemplate();

    @Autowired
    public CyberController(JWTRepository jwtRepository) {
        this.jwtRepository = jwtRepository;
    }

    @RequestMapping("/")
    public ModelAndView landing() {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("landing.html");
        return modelAndView;
    }

    @ResponseBody
    @RequestMapping("/basic-authentication")
    public ModelAndView basic() {
        jwtRepository.erase();
        jwtRepository.setUser("basic-auth-user");
        String token = jwtRepository.loadToken();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization", "Bearer " + token);
        HttpEntity entity = new HttpEntity(httpHeaders);

        String url = base + ":" + port + context + path;
        logger.debug("Issuing {} on {}", HttpMethod.GET, url);
        ResponseEntity<UserData> responseEntity;

        try{
            responseEntity = restTemplate.exchange(url, HttpMethod.GET, entity, UserData.class);
        }catch(Exception e){
            logger.error("Basic Auth JWt call failed {}",e);
            ModelAndView mav = new ModelAndView();
            mav.setViewName("oops.html");
            mav.addObject("message",e.getMessage());
            return mav;
        }

        UserData data = responseEntity.getBody();

        ModelAndView mav = new ModelAndView();
        mav.setViewName("auth.html");
        mav.addObject("type","Basic Authentication");
        mav.addObject("name", data.getName());
        return mav;
    }

    @ResponseBody
    @RequestMapping("/digest-authentication")
    public ModelAndView digest() {
        jwtRepository.erase();
        jwtRepository.setUser("digest-auth-user");
        String token = jwtRepository.loadToken();

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization", "Bearer " + token);
        HttpEntity entity = new HttpEntity(httpHeaders);

        String url = base + ":" + port + context + path;
        logger.debug("Issuing {} on {}", HttpMethod.GET, url);
        ResponseEntity<UserData> responseEntity;

        try{
             responseEntity = restTemplate.exchange(url, HttpMethod.GET, entity, UserData.class);
        }catch(Exception e){
            logger.error("Digest Auth JWT call failed {}",e);
            ModelAndView mav = new ModelAndView();
            mav.setViewName("oops.html");
            mav.addObject("message",e.getMessage());
            return mav;
        }


        UserData data = responseEntity.getBody();

        ModelAndView mav = new ModelAndView();
        mav.setViewName("auth.html");
        mav.addObject("type","Digest Authentication");
        mav.addObject("name", data.getName());
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

}
