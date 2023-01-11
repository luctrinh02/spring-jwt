package com.tutorial.jwt.services;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.tutorial.jwt.entities.User;
import com.tutorial.jwt.repositories.UserRepository;

@Service
public class CustomUserDetailService implements UserDetailsService{
	private UserRepository repository;
	
	public CustomUserDetailService(UserRepository repository) {
		super();
		this.repository = repository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user=repository.findByUsername(username);
		if(user==null ) {
			throw new UsernameNotFoundException("Không tồn tại người dùng "+username);
		}
		return org.springframework.security.core.userdetails.User.builder().username(user.getUsername())
				.password(user.getPassword()).authorities("ADMIN").disabled(user.getDisable()).build();
		
	}
	
}
