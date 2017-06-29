package com.gft.oauth2.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import com.gft.oauth2.model.Authority;

@Transactional
public interface AuthorityRepository extends JpaRepository<Authority, Integer> {

}
