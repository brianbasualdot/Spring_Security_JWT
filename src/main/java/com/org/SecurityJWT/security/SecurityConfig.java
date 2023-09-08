package com.org.SecurityJWT.security;

import com.org.SecurityJWT.security.filters.JwtAuthenticationFilter;
import com.org.SecurityJWT.security.filters.JwtAuthorizationFilter;
import com.org.SecurityJWT.security.jwt.JwtUtils;
import com.org.SecurityJWT.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    JwtAuthorizationFilter authorizationFilter;

    @Bean       // Comportamiento de acceso a los endpoints y el manejo de la sesion
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtUtils);
        JwtAuthenticationFilter.setAuthenticationManager(authenticationManager);
        JwtAuthenticationFilter.setFilterProccesUrl("/login");

        return httpSecurity
                .csrf(config -> config.disable())
                        .authorizeHttpRequests(auth -> {
                            auth.requestMatchers("/hello").permitAll(); // Este endpoint deberia ser publico
                            auth.anyRequest().authenticated(); // pero los demas no
                        })
                .sessionManagement(session -> {
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                .addFilter(jwtAuthenticationFilter)
                .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

/*
    // Con un usuario en memoria (aqui debajo)
    @Bean
    UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("anonimous")
                .password("0000")
                .roles()
                .build());

        return manager;
    }

 */

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // es el objeto que se encarga de administrar la autenticacion en la api. Y nos exige manejar un PasswordEncoder (Arriba)
    @Bean
    AuthenticationManager authenticationManager(HttpSecurity httpSecurity, PasswordEncoder passwordEncoder) throws Exception {
        return httpSecurity.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder)
                .and().build();
    }
}
