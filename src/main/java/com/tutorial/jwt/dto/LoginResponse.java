package com.tutorial.jwt.dto;

import com.tutorial.jwt.entities.User;

public class LoginResponse extends User{
	private String token;
	
	public LoginResponse() {
		super();
	}
	
	public LoginResponse(Integer id, String username, String password, String role, Boolean disable, String token) {
		super(id, username, password, role, disable);
		this.token = token;
	}

	public LoginResponse(String token) {
		super();
		this.token = token;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
	
}
