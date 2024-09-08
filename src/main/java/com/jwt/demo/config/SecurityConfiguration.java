package com.jwt.demo.config;

import com.jwt.demo.component.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Configuration class for setting up security-related configurations, such as authentication and CORS policies.
 *
 * This class leverages Spring Security to define the security filter chain, configure JWT authentication, and manage CORS settings.
 * It customizes how the application handles authentication and authorization for different endpoints,
 * and integrates JWT-based security.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Constructor to inject the {@link AuthenticationProvider} and {@link JwtAuthenticationFilter}.
     *
     * @param authenticationProvider The provider responsible for authenticating users.
     * @param jwtAuthenticationFilter The filter responsible for processing JWT tokens in requests.
     */
    public SecurityConfiguration(AuthenticationProvider authenticationProvider, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.authenticationProvider = authenticationProvider;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    /**
     * Configures the security filter chain to define how requests are secured and authenticated.
     *
     * @param http The {@link HttpSecurity} object used to configure security behavior.
     *
     * @return A configured {@link SecurityFilterChain} object that defines how security is applied.
     *
     * @throws Exception If an error occurs while configuring the security chain.
     *
     * This method configures the following:
     * <ul>
     *   <li>Disables CSRF protection since the application uses JWT tokens for stateless authentication.</li>
     *   <li>Allows unrestricted access to any endpoint under "/auth/**", which is typically used for authentication/registration.</li>
     *   <li>Requires authentication for all other requests.</li>
     *   <li>Configures session management to be stateless (as JWT-based authentication is stateless).</li>
     *   <li>Adds the custom {@link JwtAuthenticationFilter} to process JWT tokens before the {@link UsernamePasswordAuthenticationFilter}.</li>
     *   <li>Sets the custom {@link AuthenticationProvider} to handle user authentication.</li>
     * </ul>
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Configures CORS (Cross-Origin Resource Sharing) settings for the application.
     *
     * @return A {@link CorsConfigurationSource} object that defines the allowed origins, methods, and headers for CORS.
     *
     * This method defines the following CORS settings:
     * <ul>
     *   <li>Allows requests from "http://localhost:8080".</li>
     *   <li>Permits HTTP GET and POST methods.</li>
     *   <li>Allows "Authorization" and "Content-Type" headers in requests.</li>
     * </ul>
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(List.of("http://localhost:8080"));
        corsConfiguration.setAllowedMethods(List.of("GET", "POST"));
        corsConfiguration.setAllowedHeaders(List.of("Authorization", "Content-Type"));

        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

        return urlBasedCorsConfigurationSource;
    }
}

