# Login REST API using Spring Boot, Spring Security, Hibernate and MySQL Database

### 1.Tools and Technologies Used
* Spring boot 3
* Spring tool suite 4/Eclipse
* Spring security 6
* Mysql
* Spring data jpa
* Hybernate
* Maven
### 2.Dependency
```php
<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.thymeleaf.extras</groupId>
			<artifactId>thymeleaf-extras-springsecurity6</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>com.nimbusds</groupId>
			<artifactId>nimbus-jose-jwt</artifactId>
			<version>9.27</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-configuration-processor</artifactId>
		</dependency>
		<dependency>
			<groupId>mysql</groupId>
			<artifactId>mysql-connector-java</artifactId>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
```
### 3.Configure Mysql in application.properties
```
spring.datasource.url = jdbc:mysql://localhost:3306/db_example10
spring.datasource.username =root
#if your Mysql has a password. Fill it in here
spring.datasource.password =
spring.jpa.properties.hibernate.dialect = org.hibernate.dialect.MySQLDialect
spring.jpa.hibernate.ddl-auto = update
```
You can add this `logging.level.org.springframework.security=TRACE` for see level TRACE of security log
### 4.Create User Entity
```
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
}
```
### 5.Create Repository
```
@Repository
public interface UserRepository extends JpaRepository<User, Integer>{
	User findByUsername(String username);
}
```
### 6.Create custom UserDetailService
```
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
			throw new UsernameNotFoundException("User not found: "+username);
		}
		return org.springframework.security.core.userdetails.User.builder().username(user.getUsername())
				.password(user.getPassword()).roles(user.getRole()).disabled(user.getDisable()).build();
	}
}
```
### 7.Create AuthenticationExceptionHandler
Create class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint
```
@Component("customAuthenticationEntryPoint")
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint{
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().println(authException.getMessage());
	}
}
```
### 8.Create privatekey and publickey
In resource, create a folder name **certs** to save public key and private key.
In this case, I use **OpenSSl** to create key.
if you don't have it installed. You can find it [here.](https://code.google.com/archive/p/openssl-for-windows/downloads).
`Remember: put src to bin folder of openssl to PATH in Environment Variables`
Open cmd by `Window+R` type **cmd**
Move to **certs** folder
`Excample: cd C:\Users\NTS\Documents\workspace-spring-tool-suite-4-4.15.1.RELEASE\Spring-JWT\src\main\resources\certs`
##### Step 1: Create keypair.pem
`openssl genrsa -out keypair.pem 2048`
##### Step 2: Create public.pem
`openssl rsa -in keypair.pem -pubout -out public.pem`
##### Step 3: Create private.pem
`openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem`
Exit **cmd** by `exit`
### 9.Configure RSA Properties
##### Step 1: Configure in application.properties
```
rsa.private-key=classpath:certs/private.pem
rsa.public-key=classpath:certs/public.pem
```
If it have warings `is an unknown property`. Do not mind
##### Step 2: Create RSAProperties class
```
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
```
`Notice`:To use **@ConfigurationProperties** you must add dependency spring-boot-configuration-processor and add `@EnableConfigurationProperties(RSAProperties.class)` to the Spring Application class
```
@EnableConfigurationProperties(RSAProperties.class)
@SpringBootApplication
public class SpringJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtApplication.class, args);
	}

}
```
### 10.Configure Spring security
Remember add anotation @EnableWebSecurity in security configure class
```
@Configuration
@EnableWebSecurity
public class Config {
	@Autowired
	private RSAProperties properties;
	@Autowired
    @Qualifier("customAuthenticationEntryPoint")
    private AuthenticationEntryPoint authEntryPoint;
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.csrf(t -> t.disable())
				.authorizeHttpRequests(
						auth -> auth.requestMatchers("/user/login").permitAll().anyRequest().authenticated())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.httpBasic(Customizer.withDefaults())
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
				.exceptionHandling().authenticationEntryPoint(authEntryPoint).and()
				.logout().permitAll().invalidateHttpSession(true).deleteCookies("JSESSIONID")
				.and()
				.build();
	}
	
	@Bean
	public JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withPublicKey(properties.getPublicKey()).build();
	}

	@Bean
	public JwtEncoder jwtEncoder() {
		JWK jwk = new RSAKey.Builder(properties.getPublicKey()).privateKey(properties.getPrivateKey()).build();
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}
}
```
`Notice:`In Spring Security 6. Prefix of authority is "SCOPE_". If you put user with roles("role"), In fact, authority is "SCOPE_ROLE_role"
### 11.Create DTO class
##### Request
```
public class LoginDto {
	private String username;
	private String password;
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
}	
```
##### Response
```
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
```
### 12.Create Api
```
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
```
### 13.Testing
In Mysql, I have two users:
If you want to insert a user to Mysql you must decode your passord by BCrypt
Example: **123456789** is **$2a$12$gphoX7gniymUQ.UtuoNUxuiPK7wlQY6GSQdbZRbPeW5ceFn9PL4yS** in BCrypt
1. **admin1** & **123456789**
2. **admin2** & **123456789** and this user is disabled
##### Login fail
* Wrong user or passord
![image](https://user-images.githubusercontent.com/108512945/210693726-21082e89-f712-498b-8f05-c60eb934b9f3.png)
* User disabled
![image](https://user-images.githubusercontent.com/108512945/210693858-16e78252-c1ff-4f3c-a8e8-5a022c58f3aa.png)
* Un authorized
![image](https://user-images.githubusercontent.com/108512945/210693932-f9732792-aa73-43ac-b1d1-0b1cd412d0da.png)
##### Login success
![image](https://user-images.githubusercontent.com/108512945/210694492-d3f1b52e-f0ed-4612-afb9-9d1c68ff0e04.png)
##### Access to 'user/id' by token
You can use tab Authorization and select BearerToken to put the token in
![image](https://user-images.githubusercontent.com/108512945/210694864-f4500e0e-b4fa-4792-b3c4-e61a88311c9c.png)
Anothor way. You can add Authorization header with value **Bearer token** like this:
![image](https://user-images.githubusercontent.com/108512945/210695466-0f5febd3-3627-4dd7-a402-8b0cc1d53617.png)
### 14.Summary
If you using JWT for authentication. You don't need to pay attention to 'session'. Logging out is the client's job. So we can't destroy the token if it in expiry. But I usually save the token on Redis. So I can add another TokenFilter to checking it. I will explain how to do it in the next post. Thank you for reading! See yah

`Reference:`[https://docs.spring.io/spring-security/reference/index.html](https://docs.spring.io/spring-security/reference/index.html)