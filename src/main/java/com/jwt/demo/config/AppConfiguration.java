package com.jwt.demo.config;

import com.jwt.demo.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration class for setting up authentication-related beans in the application.
 *
 * This class defines several beans required for user authentication, including:
 * <ul>
 *   <li>{@link UserDetailsService}: Loads user-specific data during authentication.</li>
 *   <li>{@link BCryptPasswordEncoder}: Provides password encoding and verification using the BCrypt algorithm.</li>
 *   <li>{@link AuthenticationManager}: Handles authentication requests and delegates to the appropriate provider.</li>
 *   <li>{@link AuthenticationProvider}: Provides the actual authentication logic using a user details service and a password encoder.</li>
 * </ul>
 *
 * These beans are used by the Spring Security framework to manage user authentication and authorization.
 */
@Configuration
public class AppConfiguration {
    private final UserRepository userRepository;

    public AppConfiguration(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Defines and configures the {@link UserDetailsService} bean, which is responsible for loading user-specific
     * data during authentication.
     *
     * @return A {@link UserDetailsService} that retrieves a user by their email (username) from the {@link UserRepository}.
     *
     * This method returns a {@link UserDetailsService} implementation that:
     * <ul>
     *   <li>Uses the provided username (email) to search for a user in the {@link UserRepository}.</li>
     *   <li>If a user is found, it returns the user's details for authentication purposes.</li>
     *   <li>If no user is found, it throws a {@link UsernameNotFoundException} with a message "User not found".</li>
     * </ul>
     *
     * This service is typically used by the authentication provider to load user details during the login process.
     *
     * @throws UsernameNotFoundException if no user is found with the provided email (username).
     */
    @Bean
    UserDetailsService userDetailsService(){
        return username -> userRepository
                .findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }


    /**
     * Defines and configures the {@link BCryptPasswordEncoder} bean, which is used to encode and decode passwords.
     *
     * @return A new instance of {@link BCryptPasswordEncoder}, which provides strong password hashing using
     *         the BCrypt algorithm.
     *
     * This method returns a {@link BCryptPasswordEncoder} that will be used in the application to securely hash
     * passwords before storing them and to verify user credentials during authentication.
     *
     * BCrypt is a password hashing function designed to be computationally expensive, making it resistant to
     * brute-force attacks.
     */
    @Bean
    BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * Defines and configures the {@link AuthenticationManager} bean, which is responsible for handling
     * authentication requests.
     *
     * @param config The {@link AuthenticationConfiguration} that provides access to the current authentication
     *               setup in the application.
     *
     * @return The {@link AuthenticationManager} retrieved from the provided {@link AuthenticationConfiguration}.
     *
     * @throws Exception If there is an error during the retrieval of the {@link AuthenticationManager}.
     *
     * This method extracts the {@link AuthenticationManager} from the provided {@link AuthenticationConfiguration}.
     * The {@link AuthenticationManager} is used to authenticate users based on the provided authentication provider
     * (e.g., {@link DaoAuthenticationProvider}) and configuration.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Defines and configures the authentication provider bean used for authenticating users.
     *
     * @return An {@link AuthenticationProvider} configured with a {@link DaoAuthenticationProvider},
     *         which uses the custom {@link UserDetailsService} and password encoder for user authentication.
     *
     * This method performs the following steps:
     * <ul>
     *   <li>Creates a new instance of {@link DaoAuthenticationProvider}.</li>
     *   <li>Sets the {@link UserDetailsService} responsible for retrieving user-specific data.</li>
     *   <li>Sets the password encoder to be used for encoding and verifying user passwords.</li>
     *   <li>Returns the configured {@link AuthenticationProvider}.</li>
     * </ul>
     *
     * The {@link DaoAuthenticationProvider} uses the {@link UserDetailsService} to load user details
     * from the database and the {@link PasswordEncoder} to check if the provided password matches the stored one.
     */
    @Bean
    AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }
}
