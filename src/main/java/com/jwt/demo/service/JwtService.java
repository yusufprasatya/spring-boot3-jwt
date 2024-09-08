package com.jwt.demo.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service class for managing JSON Web Tokens (JWTs).
 *
 * This service provides functionality for creating, parsing, and validating JWTs. It handles operations such as
 * extracting claims, generating tokens, and checking token validity. The secret key and expiration time for JWTs
 * are configurable through application properties.
 */
@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private Long jwtExpiretion;

    /**
     * Extracts the username (subject) from the JWT token.
     *
     * @param token The JWT token from which to extract the username.
     * @return The username extracted from the token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts a specific claim from the JWT token.
     *
     * @param <T> The type of the claim to be extracted.
     * @param token The JWT token from which to extract the claim.
     * @param claimsResolver A function to extract the claim from the {@link Claims} object.
     * @return The extracted claim.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generates a new JWT token for the specified user details.
     *
     * @param userDetails The user details for whom the token is being generated.
     * @return The generated JWT token.
     */
    public String generateToken(UserDetails userDetails) {
        System.out.println("generate token " + userDetails.getUsername());
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Retrieves the JWT token expiration time.
     *
     * @return The expiration time of the JWT token in milliseconds.
     */
    public Long getExpirationTime() {
        return jwtExpiretion;
    }

    /**
     * Generates a new JWT token with additional claims for the specified user details.
     *
     * @param extraClaims Additional claims to be included in the token.
     * @param userDetails The user details for whom the token is being generated.
     * @return The generated JWT token.
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiretion);
    }

    /**
     * Validates the JWT token by checking its username and expiration.
     *
     * @param token The JWT token to be validated.
     * @param userDetails The user details to check against the token.
     * @return {@code true} if the token is valid, {@code false} otherwise.
     */
    public Boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equalsIgnoreCase(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Checks if the provided JWT token has expired.
     *
     * This method determines whether the token's expiration date has passed by comparing it to the current date and time.
     *
     * @param token The JWT token to check for expiration.
     * @return {@code true} if the token has expired, {@code false} otherwise.
     *
     * The method extracts the expiration date from the token using {@link #extractExpiration(String)} and compares it
     * to the current date. If the expiration date is before the current date, the token is considered expired.
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extracts the expiration date from the provided JWT token.
     *
     * This method retrieves the expiration date claim from the JWT token. The expiration date indicates when the token
     * is no longer valid.
     *
     * @param token The JWT token from which to extract the expiration date.
     * @return The expiration date of the token as a {@link Date} object.
     *
     * The method uses {@link #extractClaim(String, Function)} to retrieve the expiration claim from the token's claims.
     * This date represents the time at which the token will expire and is used to determine whether the token is still valid.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Constructs a JWT token with the specified claims, user details, and expiration time.
     *
     * This method creates a JWT token by setting the claims, subject (username), issued date, and expiration date.
     * It signs the token using the HMAC-SHA256 algorithm and the configured signing key.
     *
     * @param extraClaims Additional claims to include in the JWT token.
     * @param userDetails The user details to be included as the subject of the token.
     * @param jwtExpiration The expiration time of the token in milliseconds from the current time.
     * @return The generated JWT token as a {@link String}.
     *
     * The token is built with the following components:
     * <ul>
     *   <li>Claims specified in {@code extraClaims}.</li>
     *   <li>The username (subject) obtained from {@code userDetails}.</li>
     *   <li>The issued date set to the current time.</li>
     *   <li>The expiration date set to the current time plus {@code jwtExpiration}.</li>
     * </ul>
     * The token is signed using the HMAC-SHA256 algorithm and the key obtained from {@link #getSignInKey()}.
     */
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            Long jwtExpiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extracts all claims from the provided JWT token.
     *
     * This method parses the JWT token using the signing key to validate its signature and then extracts the claims
     * contained within the token. The claims include various pieces of information about the token, such as its subject,
     * issued date, and expiration date.
     *
     * @param token The JWT token from which to extract the claims.
     * @return A {@link Claims} object containing all the claims from the JWT token.
     *
     * The JWT token is parsed using the signing key to ensure its validity. If the token is valid, its claims are
     * extracted and returned as a {@link Claims} object. If the token is invalid or has been tampered with, this method
     * will throw an exception.
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Retrieves the signing key used for JWT token creation and validation.
     *
     * This method decodes the base64-encoded secret key from the application properties and creates a {@link Key}
     * object using the HMAC-SHA algorithm. This key is used to sign and verify JWT tokens to ensure their authenticity
     * and integrity.
     *
     * @return A {@link Key} object used for signing JWT tokens.
     *
     * The secret key is expected to be provided as a base64-encoded string in the application properties. This method
     * decodes the string and converts it into a {@link Key} object suitable for use with the HMAC-SHA algorithm.
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

