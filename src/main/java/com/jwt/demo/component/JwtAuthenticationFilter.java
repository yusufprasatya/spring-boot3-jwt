package com.jwt.demo.component;

import com.jwt.demo.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

/**
 * A filter that intercepts each HTTP request to check for a valid JWT token in the "Authorization" header.
 *
 * This class extends {@link OncePerRequestFilter}, meaning it will only be executed once per request within a single request chain.
 * It is responsible for validating the JWT token and setting the appropriate authentication in the Spring Security context.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private HandlerExceptionResolver exceptionResolver;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * Constructor for injecting dependencies.
     *
     * @param jwtService       Service for handling JWT operations, such as extracting usernames and validating tokens.
     * @param userDetailsService Service for loading user-specific data based on the username.
     */
    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Filters each incoming HTTP request to check if it contains a valid JWT in the "Authorization" header.
     *
     * @param request       The incoming HTTP request.
     * @param response      The HTTP response.
     * @param filterChain   The filter chain to pass the request/response to the next filter in case no further
     *                      processing is required.
     *
     * @throws ServletException if an error occurs during request processing.
     * @throws IOException      if an input or output error occurs during the filter process.
     *
     * This method performs the following steps:
     * <ul>
     *   <li>Retrieves the "Authorization" header from the HTTP request.</li>
     *   <li>If the header is missing or does not start with "Bearer ", the request is passed to the next filter.</li>
     *   <li>If the header contains a JWT token, it is extracted and the username is retrieved from the token.</li>
     *   <li>Checks whether the user is authenticated and, if not, validates the token and sets up a security context with the user's details.</li>
     *   <li>If token validation passes, it assigns the user's authentication details to the {@link SecurityContextHolder}.</li>
     *   <li>Proceeds with the filter chain.</li>
     * </ul>
     *
     * If an exception occurs during processing, it is propagated upwards.
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extract the JWT token
            String jwt = authHeader.substring(7);
            System.out.println("jwt " + jwt);
            jwt = jwt.substring(7);  // Reprocess if necessary
            System.out.println("after " + jwt);

            // Extract the username from the JWT token
            final String userEmail = jwtService.extractUsername(jwt);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // If the username is present and the user is not yet authenticated
            if (userEmail != null && authentication == null) {
                System.out.println("email " + userEmail);

                // Load the user details from the user details service
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                System.out.println(userDetails.getUsername());

                // Validate the token and authenticate the user
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    // Set authentication details and store in security context
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
            // Proceed with the filter chain
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            throw e;
        }
    }
}

