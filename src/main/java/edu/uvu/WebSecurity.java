package edu.uvu;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import edu.uvu.cybersecurity.security.providers.BasicAuthProvider;
import edu.uvu.cybersecurity.security.JWTRepository;
import edu.uvu.cybersecurity.security.session.UserService;

import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;


@Configuration
@EnableWebSecurity(debug = true)
public class WebSecurity extends WebSecurityConfigurerAdapter {

    Logger logger = LoggerFactory.getLogger(WebSecurity.class);

    @Autowired
    UserService userDetailsService;

    @Bean
    public FilterChainProxy authFilters() throws Exception {

        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/")));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/basic-authentication/**"),
                basicAuthenticationFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/digest-authentication/**"),
                digestAuthenticationFilter()));
        return new FilterChainProxy(chains);
    }

    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable().formLogin().disable()
                .exceptionHandling()
                .defaultAuthenticationEntryPointFor(basicAuthenticationEntryPoint(), new AntPathRequestMatcher("/basic-authentication/**"))
                .defaultAuthenticationEntryPointFor(digestAuthenticationEntryPoint(), new AntPathRequestMatcher("/digest-authentication/**"))

                .and()
                .addFilterAt(authFilters(), BasicAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/").anonymous()
                .antMatchers("/images/**").permitAll()
                .antMatchers("/error").permitAll()
                .antMatchers("/basic/error").permitAll()
                .antMatchers("/digest/error").permitAll()
                .antMatchers("/basic-authentication/**").authenticated()
                .antMatchers("/digest-authentication/**").authenticated()
                .anyRequest().denyAll()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(basicAuthProvider());
    }

    @Bean
    BasicAuthProvider basicAuthProvider() {
        return new BasicAuthProvider(userDetailsService);
    }

    @Bean
    public DigestAuthenticationEntryPoint digestAuthenticationEntryPoint() {
        DigestAuthenticationEntryPoint entryPoint = new DigestAuthenticationEntryPoint();
        entryPoint.setKey("acegi");
        entryPoint.setRealmName("digest-realm");
        entryPoint.setNonceValiditySeconds(1800);
        return entryPoint;
    }

    @Bean
    public BasicAuthenticationEntryPoint basicAuthenticationEntryPoint() {
        BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
        entryPoint.setRealmName("basic-realm");
        return entryPoint;
    }

    @Bean
    public BasicAuthenticationFilter basicAuthenticationFilter() throws Exception {
        BasicAuthenticationFilter filter = new BasicAuthenticationFilter(authenticationManager(), basicAuthenticationEntryPoint());
        return filter;
    }

    @Bean
    public DigestAuthenticationFilter digestAuthenticationFilter() {
        DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
        filter.setUserDetailsService(userDetailsService);
        filter.setAuthenticationEntryPoint(digestAuthenticationEntryPoint());
        filter.setCreateAuthenticatedToken(true);
        return filter;
    }

    @Bean
    public JWTRepository jwtRepository() {
        logger.debug("Instantiating repository for subject {}", "uvu-cyber-user");
        return new JWTRepository("uvu-cyber-security", "this-is-a-secret", 1800);
    }

}
