package com.smartlogix.inventory.config;

import com.smartlogix.inventory.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/inventory/**")
                        .hasAnyAuthority("ROLE_ADMIN", "ROLE_WAREHOUSE_MANAGER", "ROLE_USER")

                        .requestMatchers(HttpMethod.POST, "/api/inventory/**")
                        .hasAnyAuthority("ROLE_ADMIN", "ROLE_WAREHOUSE_MANAGER")

                        .requestMatchers(HttpMethod.PUT, "/api/inventory/**")
                        .hasAnyAuthority("ROLE_ADMIN", "ROLE_WAREHOUSE_MANAGER")

                        .requestMatchers(HttpMethod.DELETE, "/api/inventory/**")
                        .hasAuthority("ROLE_ADMIN")

                        .anyRequest().authenticated()
                );

        return http.build();
    }
}
