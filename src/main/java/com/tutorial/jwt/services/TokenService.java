package com.tutorial.jwt.services;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {
	private final JwtEncoder jwtEncoder;
	private final JwtDecoder jwtDecoder;
	
	public TokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) {
		super();
		this.jwtEncoder = jwtEncoder;
		this.jwtDecoder = jwtDecoder;
	}

	public String generateToken(Authentication authentication) {
		Instant now = Instant.now();
		// @formatter:off
		String scope = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(" "));
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer("self")
				.issuedAt(now)
				.expiresAt(now.plus(1, ChronoUnit.HOURS))
				.subject(authentication.getName())
				.claim("scope", scope)
				.build();
		// @formatter:on
		return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}
	public Map<String, Object> decode(String token) {
		Jwt jwt=jwtDecoder.decode(token);
		return jwt.getClaims();
	}
}
