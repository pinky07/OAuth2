package com.gft.oauth2.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Returns user information
 *
 * @author Ruben Jimenez
 */
@RestController
public class UserInfoControlller {

    private Logger logger = LoggerFactory.getLogger(UserInfoControlller.class);

    @RequestMapping("/userInfo")
    public ResponseEntity<Principal> user(Principal principal) {
        logger.debug("user({})", principal);
        return new ResponseEntity<>(principal, HttpStatus.OK);
    }
}
