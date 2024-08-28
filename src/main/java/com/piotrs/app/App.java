package com.piotrs.app;

import org.mindrot.jbcrypt.BCrypt;

public class App
{
    public static void main(String[] args) {
        String password = "mySecurePassword";

        // Generate a salt and hash the password with it
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

        // Print the hashed password (which includes the salt)
        System.out.println("Hashed Password: " + hashedPassword);

        // Verify the password
        boolean isPasswordMatch = BCrypt.checkpw(password, hashedPassword);
        System.out.println("Password Match: " + isPasswordMatch);
    }
}
