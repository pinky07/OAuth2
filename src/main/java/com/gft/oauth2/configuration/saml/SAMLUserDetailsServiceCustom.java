package com.gft.oauth2.configuration.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mlyz on 6/5/2017.
 */

@Service
public class SAMLUserDetailsServiceCustom implements SAMLUserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(SAMLUserDetailsServiceCustom.class);

    // @Autowired
    // private UserService userService;

    @Override
    public Object loadUserBySAML(SAMLCredential samlCredential) throws UsernameNotFoundException {

        // Get user attributes from SAML
        String userEmail = samlCredential.getAttributeAsString("email");
        String userFirstName = samlCredential.getAttributeAsString("givenName");
        String userLastName = samlCredential.getAttributeAsString("surname");

        // Log data
        log.info(String.format("An user has logged in. Email: %s. First Name: %s. Last Name:  %s ",
                userEmail,
                userFirstName,
                userLastName));

        // Fetch user authorities
        List<GrantedAuthority> authorities = new ArrayList<>();
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(authority);

        // This code should help to get authorities from the db
        // =========================================================================
        // List<GrantedAuthority> authorities =
        // userService.getUserAuthorities(userEmail)
        // .stream()
        // .map(authority -> new SimpleGrantedAuthority(authority.getName()))
        // .collect(Collectors.toList());
        // =========================================================================

        return new SAMLUser(userEmail, userFirstName, userLastName, authorities);
    }
}
