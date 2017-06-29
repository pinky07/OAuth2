package com.gft.oauth2.configuration.saml;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * Extends the User class so that Spring's principal supports the user's first and last name too.
 *
 * @author Ruben Jimenez
 */
public class SAMLUser extends User {

    // User's first name
    private String firstName;

    // User's last name
    private String lastName;

    /**
     * Creates a new
     *
     * @param username
     * @param firstName
     * @param lastName
     * @param authorities
     */
    public SAMLUser(String username, String firstName, String lastName,
                    Collection<? extends GrantedAuthority> authorities) {
        // TODO Determine how not to pass an empty password
        super(username, "", true, true, true, true, authorities);
        this.firstName = firstName;
        this.lastName = lastName;
    }

    /**
     * Returns the user's first name.
     *
     * @return User's first name
     */
    public String getFirstName() {
        return firstName;
    }

    /**
     * Sets the user's first name.
     *
     * @param firstName New user's first name
     */
    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    /**
     * Returns the user's last name.
     *
     * @return User's last name
     */
    public String getLastName() {
        return lastName;
    }

    /**
     * Sets the user's last name.
     *
     * @param lastName New user's last name
     */
    public void setLastName(String lastName) {
        this.lastName = lastName;
    }
}
