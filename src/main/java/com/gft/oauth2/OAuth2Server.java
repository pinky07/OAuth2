package com.gft.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

/**
 * Spring Boot Application. Starts an OAuth2 authorization server. Registers the
 * application with Eureka.
 * 
 * @author Ruben Jimenez
 * @author Manuel Yepez
 * @Author Riccardo Bove
 */
@SpringBootApplication
@EnableAuthorizationServer
@EnableDiscoveryClient
public class OAuth2Server {

	/**
	 * Application's entry point.
	 * 
	 * @param args
	 *            System arguments
	 */
	public static void main(String[] args) {
		SpringApplication.run(OAuth2Server.class, args);
	}



}
