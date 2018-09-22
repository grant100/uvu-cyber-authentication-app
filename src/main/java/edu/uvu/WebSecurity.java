package edu.uvu;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

import edu.uvu.cybersecurity.security.filters.JWTAuthenticationFilter;
import edu.uvu.cybersecurity.security.providers.BasicAuthProvider;
import edu.uvu.cybersecurity.security.JWTRepository;
import edu.uvu.cybersecurity.security.providers.JWTAuthProvider;
import edu.uvu.cybersecurity.security.session.UserService;

import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;


@Configuration
@EnableWebSecurity(debug = true)
public class WebSecurity extends WebSecurityConfigurerAdapter {


    @Value("${uvu.security.username}")
    private String username;

    @Value("${uvu.security.password}")
    private String password;

    Logger logger = LoggerFactory.getLogger(WebSecurity.class);

    @Autowired
    UserService userDetailsService;

    @Bean
    public FilterChainProxy authFilters() throws Exception {

        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/")));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/challenge-one"),
                basicAuthenticationFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/challenge-two"),
                digestAuthenticationFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/challenge-three"),
                basicAuthenticationFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/challenge-four"),
                jwtAuthenticationFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/challenge-five"),
                basicAuthenticationFilter()));

        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/basic-authentication/**"),
                basicAuthenticationFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/digest-authentication/**"),
                digestAuthenticationFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/token-authentication/**"),
               jwtAuthenticationFilter()));


        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/super-admin"), basicAuthenticationFilter()));

        return new FilterChainProxy(chains);
    }

    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable().formLogin().disable()
                .exceptionHandling()
                .defaultAuthenticationEntryPointFor(basicAuthenticationEntryPoint(), new AntPathRequestMatcher("/basic-authentication/**"))
                .defaultAuthenticationEntryPointFor(digestAuthenticationEntryPoint(), new AntPathRequestMatcher("/digest-authentication/**"))

                .defaultAuthenticationEntryPointFor(basicAuthenticationEntryPoint(), new AntPathRequestMatcher("/challenge-one/**"))
                .defaultAuthenticationEntryPointFor(digestAuthenticationEntryPoint(), new AntPathRequestMatcher("/challenge-two/**"))
                .defaultAuthenticationEntryPointFor(basicAuthenticationEntryPoint(), new AntPathRequestMatcher("/challenge-three/**"))
                .defaultAuthenticationEntryPointFor(basicAuthenticationEntryPoint(), new AntPathRequestMatcher("/challenge-five/**"))
                .and()
                .addFilterAt(authFilters(), BasicAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/").anonymous()
                .antMatchers("/images/**").permitAll()
                .antMatchers("/error").permitAll()
                .antMatchers("/token/error").permitAll()
                .antMatchers("/basic/error").permitAll()
                .antMatchers("/digest/error").permitAll()

                .antMatchers("/basic-authentication/**").hasAnyAuthority("ROLE_BASIC")
                .antMatchers("/digest-authentication/**").hasAnyAuthority("ROLE_DIGEST")
                .antMatchers("/token-authentication/**").hasAnyAuthority("ROLE_TOKEN")

                .antMatchers("/challenge-one").hasAnyAuthority("ROLE_ONE")
                .antMatchers("/challenge-two").hasAnyAuthority("ROLE_TWO")
                .antMatchers("/challenge-three").hasAnyAuthority("ROLE_THREE")
                .antMatchers("/challenge-four").hasAnyAuthority("ROLE_FOUR")
                .antMatchers("/challenge-five").hasAnyAuthority("ROLE_FIVE")

                .antMatchers("/super-admin").hasAnyAuthority("ROLE_SUPER_ADMIN")
                .antMatchers("/**").hasAnyAuthority("ROLE_USER")
                .anyRequest().denyAll()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(basicAuthProvider());
        auth.authenticationProvider(jwtAuthProvider());
    }

    @Bean
    JWTAuthProvider jwtAuthProvider() {
        return new JWTAuthProvider(userDetailsService);
    }

    @Bean
    BasicAuthProvider basicAuthProvider() {
        return new BasicAuthProvider(userDetailsService);
    }

    @Bean
    public JWTAuthenticationFilter jwtAuthenticationFilter() throws Exception{
        return new JWTAuthenticationFilter(authenticationManager());
    }

    @Bean
    public DigestAuthenticationEntryPoint digestAuthenticationEntryPoint() {
        DigestAuthenticationEntryPoint entryPoint = new DigestAuthenticationEntryPoint();
        entryPoint.setKey("acegi");
        entryPoint.setRealmName("digest-realm!");
        entryPoint.setNonceValiditySeconds(1800);
        return entryPoint;
    }

    @Bean
    public BasicAuthenticationEntryPoint basicAuthenticationEntryPoint() {
        String flag1 ="u:p "+username+" "+password;
        BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
        entryPoint.setRealmName("challenge-one {flag: "+flag1+"}");
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
