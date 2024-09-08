package com.jwt.demo.service;

import com.jwt.demo.dto.LoginUserDto;
import com.jwt.demo.dto.RegisterUserDto;
import com.jwt.demo.entity.User;
import com.jwt.demo.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Service class for handling user authentication and registration.
 *
 * This service provides methods for user registration and authentication. It interacts with the {@link UserRepository}
 * for managing user data, {@link PasswordEncoder} for encoding passwords, and {@link AuthenticationManager} for
 * authenticating users.
 */
@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    /**
     * Constructor for injecting dependencies.
     *
     * @param userRepository The repository used to manage user data.
     * @param passwordEncoder The encoder used to hash passwords.
     * @param authenticationManager The manager used for authenticating users.
     */
    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    /**
     * Registers a new user by creating a new {@link User} entity and saving it to the database.
     *
     * @param payload The {@link RegisterUserDto} containing user registration details.
     * @return The {@link User} entity that was created and saved.
     *
     * This method performs the following steps:
     * <ul>
     *   <li>Creates a new {@link User} object with the details from the {@link RegisterUserDto}.</li>
     *   <li>Encodes the user's password using the {@link PasswordEncoder}.</li>
     *   <li>Saves the user entity to the {@link UserRepository}.</li>
     *   <li>Returns the saved {@link User} entity.</li>
     * </ul>
     */
    public User signUp(RegisterUserDto payload) {
        User user = new User();
        user.setFullName(payload.getFullName());
        user.setEmail(payload.getEmail());
        user.setPassword(passwordEncoder.encode(payload.getPassword()));

        return userRepository.save(user);
    }

    /**
     * Authenticates a user by verifying their credentials and returning the user entity if authentication is successful.
     *
     * @param payload The {@link LoginUserDto} containing user login credentials.
     * @return The {@link User} entity associated with the provided email address if authentication is successful.
     *
     * @throws RuntimeException if the user is not found or authentication fails.
     *
     * This method performs the following steps:
     * <ul>
     *   <li>Uses the {@link AuthenticationManager} to authenticate the user based on the provided email and password.</li>
     *   <li>Retrieves the {@link User} entity from the {@link UserRepository} based on the email address.</li>
     *   <li>Throws a {@link RuntimeException} if no user is found with the given email address.</li>
     * </ul>
     */
    public User authenticate(LoginUserDto payload) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        payload.getEmail(),
                        payload.getPassword()
                )
        );

        return userRepository.findByEmail(payload.getEmail())
                .orElseThrow();
    }
}
