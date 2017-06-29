package com.gft.oauth2.service;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.gft.oauth2.model.Authority;
import com.gft.oauth2.model.User;
import com.gft.oauth2.repository.UserRepository;

@Repository
@Transactional
public class UserService {

	private Logger logger = LoggerFactory.getLogger(UserService.class);

	@Autowired
	private UserRepository userRepository;

	public Set<Authority> getUserAuthorities(String userEmail) {
		logger.info(String.format("getUserAuthorities(%s)", userEmail));
		Optional<User> user = userRepository.findByEmail(userEmail);
		Set<Authority> authorities = null;
		if (user.isPresent()) {
			authorities = user.get().getAuthorities();
			logger.info(String.format("Authorities are: %s",
					authorities.stream()
							.map(authority -> authority.getName())
							.collect(Collectors.joining(", "))));
		} else {
			logger.info(String.format("User %s couldn't be found", userEmail));
		}
		return authorities;
	}
}
