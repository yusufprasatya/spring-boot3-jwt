package com.jwt.demo.controller;

import com.jwt.demo.dto.LoginResponseDto;
import com.jwt.demo.dto.LoginUserDto;
import com.jwt.demo.dto.RegisterUserDto;
import com.jwt.demo.entity.User;
import com.jwt.demo.service.AuthenticationService;
import com.jwt.demo.service.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for handling authentication-related requests.
 *
 * This controller provides endpoints for user registration and login. It interacts with the {@link JwtService} for
 * generating JWT tokens and {@link AuthenticationService} for handling user authentication and registration.
 */
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    /**
     * Constructor for injecting the {@link JwtService} and {@link AuthenticationService}.
     *
     * @param jwtService The service used for generating and managing JWT tokens.
     * @param authenticationService The service used for user authentication and registration.
     */
    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    /**
     * Registers a new user in the system.
     *
     * @param payload The {@link RegisterUserDto} containing user registration details.
     * @return A {@link ResponseEntity} containing the {@link User} object of the newly registered user and
     *         an HTTP 201 (Created) status.
     *
     * This method performs the following steps:
     * <ul>
     *   <li>Uses the {@link AuthenticationService} to handle user registration based on the provided {@link RegisterUserDto}.</li>
     *   <li>Returns the registered user's details wrapped in a {@link ResponseEntity} with an HTTP 201 (Created) status.</li>
     * </ul>
     */
    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody RegisterUserDto payload) {
        User signedUp = authenticationService.signUp(payload);
        return new ResponseEntity<>(signedUp, HttpStatus.CREATED);
    }

    /**
     * Authenticates a user and generates a JWT token.
     *
     * @param payload The {@link LoginUserDto} containing user login credentials.
     * @return A {@link ResponseEntity} containing a {@link LoginResponseDto} with the JWT token and expiration time,
     *         and an HTTP 200 (OK) status.
     *
     * This method performs the following steps:
     * <ul>
     *   <li>Uses the {@link AuthenticationService} to authenticate the user based on the provided {@link LoginUserDto}.</li>
     *   <li>Generates a JWT token for the authenticated user using the {@link JwtService}.</li>
     *   <li>Creates a {@link LoginResponseDto} containing the generated token and its expiration time.</li>
     *   <li>Returns the login response wrapped in a {@link ResponseEntity} with an HTTP 200 (OK) status.</li>
     * </ul>
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginUserDto payload) {
        User authenticated = authenticationService.authenticate(payload);
        System.out.println("authhh " + authenticated.getEmail());

        // Generate JWT token
        String generatedToken = jwtService.generateToken(authenticated);

        // Create login response DTO
        LoginResponseDto loginResponseDto = new LoginResponseDto();
        loginResponseDto.setToken(generatedToken);
        loginResponseDto.setExpiresIn(jwtService.getExpirationTime());

        // Return response with token and expiration time
        return new ResponseEntity<>(loginResponseDto, HttpStatus.OK);
    }
}
