package dev.xdbe.booking.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth
                // Step 3: add authorization
                .requestMatchers("/dashboard").hasRole("ADMIN")
                .requestMatchers("/booking").permitAll()
                .anyRequest().permitAll()
            )
            // Step 3: Add login form
            .csrf((csrf) -> csrf
                .ignoringRequestMatchers("/h2-console/*")
            )
            .headers(headers -> headers.frameOptions().disable())
            .formLogin(withDefaults())
            .logout(withDefaults())
            .build();
    }

    // Step 3: add InMemoryUserDetailsManager
    @Bean
    public UserDetailsService users() {
        UserDetails admin = User.builder()
            .username("admin")
            .password("{bcrypt}$2a$10$s6nplcKHUgQe7n/c0LFws.z35cqVk9y52RSJ2./p/VhnTfp/uAEDy")
            .roles("ADMIN")
            .build();

        UserDetails user = User.builder()
            .username("user")
            .password("{bcrypt}$2a$10$s6nplcKHUgQe7n/c0LFws.z35cqVk9y52RSJ2./p/VhnTfp/uAEDy")
            .roles("USER")
            .build();

        return new InMemoryUserDetailsManager(admin, user);
    }

}