package com.jwt.demo.repository;

import com.jwt.demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for managing {@link User} entities.
 *
 * This interface extends {@link JpaRepository} to provide CRUD operations and custom query methods for {@link User} entities.
 * It includes a method for finding users by their email address.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    /**
     * Retrieves a {@link User} entity by its email address.
     *
     * @param email The email address of the user to retrieve.
     * @return An {@link Optional} containing the {@link User} if found, or an empty {@link Optional} if no user
     *         is found with the given email address.
     */
    Optional<User> findByEmail(String email);
}

