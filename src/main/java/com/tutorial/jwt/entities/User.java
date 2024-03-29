package com.tutorial.jwt.entities;

import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class User implements Serializable{
	@Id
	@GeneratedValue(strategy =GenerationType.IDENTITY)
	private Integer id;
	@Column(unique = true)
	private String username;
	private String password;
	private String role;
	private Boolean disable;
	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}
	public Boolean getDisable() {
		return disable;
	}
	public void setDisable(Boolean disable) {
		this.disable = disable;
	}
	public User(Integer id, String username, String password, String role, Boolean disable) {
		super();
		this.id = id;
		this.username = username;
		this.password = password;
		this.role = role;
		this.disable = disable;
	}
	public User() {
		super();
		// TODO Auto-generated constructor stub
	}
	
}
