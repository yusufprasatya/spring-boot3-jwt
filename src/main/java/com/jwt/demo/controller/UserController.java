package com.jwt.demo.controller;

import com.jwt.demo.entity.User;
import com.jwt.demo.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for handling user-related requests.
 *
 * This controller provides endpoints for retrieving information about the currently authenticated user.
 * It interacts with the {@link UserRepository} to perform operations related to the user.
 */
@RestController
@RequestMapping("/user")
public class UserController {

    private final UserRepository userRepository;

    /**
     * Constructor for injecting the {@link UserRepository}.
     *
     * @param userRepository The repository used to manage user data.
     */
    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Retrieves the currently authenticated user.
     *
     * @return A {@link ResponseEntity} containing the {@link User} object representing the currently authenticated user,
     *         or a response with {@link HttpStatus#UNAUTHORIZED} if no authenticated user is found.
     *
     * This method performs the following steps:
     * <ul>
     *   <li>Retrieves the current authentication object from the {@link SecurityContextHolder}.</li>
     *   <li>Extracts the {@link User} object from the authentication principal.</li>
     *   <li>Returns the authenticated user details wrapped in a {@link ResponseEntity} with an HTTP 200 (OK) status.</li>
     *   <li>If an exception occurs (e.g., the user is not authenticated), returns an HTTP 401 (Unauthorized) response.</li>
     * </ul>
     */
    @GetMapping("/me")
    public ResponseEntity<User> authenticatedUser() {
        try {
            // Get the authentication object from the security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // Get the authenticated user from the authentication principal
            User currentUser = (User) authentication.getPrincipal();

            // Return the authenticated user's details
            return new ResponseEntity<>(currentUser, HttpStatus.OK);
        } catch (Exception e) {
            // Return unauthorized if an error occurs (e.g., no authenticated user)
            return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
        }
    }
}
