package com.tutorial.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.tutorial.jwt.configs.RSAProperties;
@EnableConfigurationProperties(RSAProperties.class)
@SpringBootApplication
public class SpringJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtApplication.class, args);
	}

}
