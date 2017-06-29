package com.gft.oauth2.model;

import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;

@Entity
@Table(name = "User")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private int id;

	private String email;

	@ManyToMany(cascade = CascadeType.ALL)
	@JoinTable(
			name = "UserXAuthority",
			joinColumns = @JoinColumn(name = "userId", referencedColumnName = "id"),
			inverseJoinColumns = @JoinColumn(name = "authorityId", referencedColumnName = "id"))
	private Set<Authority> authorities;

	public User() {
	}

	public User(String email) {
		this.email = email;
	}

	public int getId() {
		return id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Set<Authority> getAuthorities() {
		return authorities;
	}
}
