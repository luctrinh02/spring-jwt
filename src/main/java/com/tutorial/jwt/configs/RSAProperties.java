package com.tutorial.jwt.configs;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rsa")
public class RSAProperties {
	private RSAPrivateKey privateKey;
	private RSAPublicKey publicKey;
	public RSAProperties(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
		super();
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}
	public RSAProperties() {
		super();
		// TODO Auto-generated constructor stub
	}
	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(RSAPrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	public RSAPublicKey getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(RSAPublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
}
