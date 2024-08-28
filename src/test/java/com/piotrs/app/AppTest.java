package com.piotrs.app;

import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;

import static org.junit.jupiter.api.Assertions.*;

class AppTest {

    @Test
    void testPasswordHashingAndVerification() {
        String password = "mySecurePassword";

        // Hash the password
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

        // Assert that the hashed password is not null or empty
        assertNotNull(hashedPassword, "Hashed password should not be null");
        assertFalse(hashedPassword.isEmpty(), "Hashed password should not be empty");

        // Verify the password matches the hash
        boolean isPasswordMatch = BCrypt.checkpw(password, hashedPassword);

        // Assert that the password matches
        assertTrue(isPasswordMatch, "Password should match the hashed password");

        // Test with an incorrect password
        String incorrectPassword = "wrongPassword";
        boolean isIncorrectPasswordMatch = BCrypt.checkpw(incorrectPassword, hashedPassword);

        // Assert that the incorrect password does not match
        assertFalse(isIncorrectPasswordMatch, "Incorrect password should not match the hashed password");
    }
}
