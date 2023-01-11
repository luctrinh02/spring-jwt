package com.tutorial.jwt.apis;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.tutorial.jwt.dto.LoginDto;
import com.tutorial.jwt.dto.LoginResponse;
import com.tutorial.jwt.entities.User;
import com.tutorial.jwt.repositories.UserRepository;
import com.tutorial.jwt.services.TokenService;


@RestController
public class AuthenticationApi {
	private static final Logger LOGGER=LoggerFactory.getLogger(AuthenticationApi.class);
	private final TokenService tokenService;
    private final UserRepository repository;
    private final AuthenticationManager manager;
    
    public AuthenticationApi(TokenService tokenService, UserRepository repository, AuthenticationManager manager) {
        super();
        this.tokenService = tokenService;
        this.repository = repository;
        this.manager = manager;
    }
	@GetMapping("/user/id")
	public ResponseEntity<?> hello(Authentication authentication) {
		return ResponseEntity.ok(authentication.getName() +" is on the system");
	}
	@PostMapping("/user/login")
	public ResponseEntity<?> login(@RequestBody LoginDto login) {
		Authentication authentication=manager.authenticate(new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
		String token=tokenService.generateToken(authentication);
		User user=repository.findByUsername(authentication.getName());
		LoginResponse loginResponse=new LoginResponse(user.getId(),user.getUsername(),null,user.getRole(),user.getDisable(),token);
		return ResponseEntity.ok(loginResponse);
	}
}
