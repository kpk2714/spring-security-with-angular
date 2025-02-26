Configure Spring Security with Angular Login and Remember Me

com.spring.security  =>  SpringSecurityWithAngularApplication.java


package com.spring.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication

public class SpringSecurityWithAngularApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityWithAngularApplication.class, args);
	}

}



com.spring.security.config  =>  SecurityBeansConfig.java


package com.spring.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration

public class SecurityBeansConfig {

	@Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}


com.spring.security.config  =>  WebSecurityConfiguration.java

package com.spring.security.config;

import java.util.List;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.spring.security.service.CustomUserDetailsService;

import jakarta.servlet.http.HttpServletResponse;

@Configuration

@EnableWebSecurity

public class WebSecurityConfiguration{
	
	private static final String REMEMBER_ME_KEY = "my-remember-me-key";
	
	@Autowired
    private CustomUserDetailsService userDetailsService;
	
	@Autowired
	private DataSource dataSource;
	
	@Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(authProvider);
    }
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		
		http.csrf(csrf -> csrf.disable())
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			.authorizeHttpRequests(auth -> auth.requestMatchers("/save","/login","/auth/logout","/user").permitAll()
									   .requestMatchers("/home").hasAuthority("ROLE_STUDENT")
									   .requestMatchers("/about").hasAuthority("ROLE_ADMIN")
									   .anyRequest().authenticated()
								  )
			
								  .formLogin(form -> form.disable())
								  .logout(logout -> logout
										  .logoutUrl("/auth/logout")
										  .logoutSuccessHandler((request, response, authentication) -> {
											  response.setStatus(HttpServletResponse.SC_OK);
										  })
										  .invalidateHttpSession(true)
										  .deleteCookies("JSESSIONID", "remember-me")
										  .permitAll()
								  )
								  .sessionManagement( session -> session
										  .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
								   )
								  .rememberMe( rememberMe -> rememberMe
										  .key(REMEMBER_ME_KEY)  // 🔴 REQUIRED! Without this, tokens are not stored.
										  .rememberMeParameter("remember-me")  // Must match frontend parameter
										  .tokenRepository(persistentTokenRepository())
										  .userDetailsService(userDetailsService)
										  .tokenValiditySeconds(40)
								  );
								 
		return http.build();
	}
	
	@Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }
	
	@Bean
	public PersistentTokenBasedRememberMeServices rememberMeServices() {
        return new PersistentTokenBasedRememberMeServices(
        		REMEMBER_ME_KEY , userDetailsService, persistentTokenRepository()
        );
    }
	
	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        	config.setAllowCredentials(true);
        	config.setAllowedOrigins(List.of("http://localhost:4200")); // Adjust based on Angular host
        	config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        	config.setAllowedHeaders(List.of("*"));
        source.registerCorsConfiguration("/**", config);
        return source;
    }

}

com.spring.security.controller  =>  LoginController.java

package com.spring.security.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")

public class LoginController {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private PersistentTokenBasedRememberMeServices rememberMeServices;

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestParam(name="username") String username, @RequestParam(name="password") String password, @RequestParam(name="remember-me") boolean rememberMe, HttpServletRequest request, HttpServletResponse response) {
		try {
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
			
			Authentication authentication = authenticationManager.authenticate(token);
			
			SecurityContext securityContext = SecurityContextHolder.getContext();
			securityContext.setAuthentication(authentication);
			request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", securityContext); // Store auth in session
			
			if(rememberMe) {
				
				rememberMeServices.loginSuccess(request, response, authentication);
			
				System.out.println("Remember Me - Token Generated!");
				UserDetails userDetails = (UserDetails)authentication.getPrincipal();
			
				System.out.println("Logged In User - "+userDetails.getUsername()+" -- "+userDetails.getPassword());
			}
			
			String role = authentication.getAuthorities().iterator().next().getAuthority();
			
			System.out.println("Remember Me Applied -> "+rememberMe);
			
			Map<String, String> responseBody = new HashMap<>();
			System.out.println("Role -> "+role);
			if (role.equals("ROLE_ADMIN")) {
				responseBody.put("redirectUrl", "/admin-dashboard");
				responseBody.put("role", role);
				responseBody.put("username", authentication.getName());
            } else if (role.equals("ROLE_STUDENT")) {
            	responseBody.put("redirectUrl", "/student-dashboard");
            	responseBody.put("role", role);
            	responseBody.put("username", authentication.getName());
            } else {
            	responseBody.put("redirectUrl", "/login"); // Default
            }
			
			return ResponseEntity.ok(responseBody);
	        
		} catch (BadCredentialsException ex) {
			
	        Map<String, String> responseBody = new HashMap<>();
	        responseBody.put("message", "Invalid username or password !");
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseBody); // Ensure JSON response
	        
	    } catch (Exception ex) {
	    	
	        Map<String, String> responseBody = new HashMap<>();
	        responseBody.put("message", "Something went wrong! Please try again.");
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
	        
	    }
	}
}


com.spring.security.controller  =>  LogoutController.java

package com.spring.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")

public class LogoutController {

	@PostMapping("/auth/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        // Invalidate session
        request.getSession().invalidate();
        
        // Clear Security Context
        SecurityContextHolder.clearContext();

        // Remove Cookies
        Cookie cookie = new Cookie("JSESSIONID", null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        // Send response
        response.setStatus(HttpServletResponse.SC_OK);
    }
}


com.spring.security.controller  =>  RegisterController.java

package com.spring.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security.entities.User;
import com.spring.security.service.CustomUserDetailsService;

@RestController

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")

public class RegisterController {
	
	@Autowired
	private CustomUserDetailsService userDetailsService;

	@PostMapping("/save")
	public User save(@RequestBody User user){
		System.out.println(user);
		return this.userDetailsService.saveUser(user);
	}
}


com.spring.security.controller  =>  UserController.java


package com.spring.security.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security.entities.User;
import com.spring.security.entities.UserResponse;
import com.spring.security.service.CustomUserDetailsService;


@RestController

@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")

public class UserController {
	
	@Autowired
	private CustomUserDetailsService customUserDetailsService;
	
	@GetMapping("/home")
	public String homePage() {
		return "This is Home Page";
	}
	
	@GetMapping("/student-dashboard")
	public String StudentPage() {
		return "This is Student Page";
	}
	
	@GetMapping("/about")
	public String AdminPage() {
		return "This is Admin Page";
	}
	
	@GetMapping("/user")
	public Map<String, Object> getUser() {
	    
		Map<String, Object> response = new HashMap<>();
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
			response.put("authenticated", false);
            return response;
        }
			
		String username = authentication.getName();
		
		System.out.println("/User -> Username + "+username);
		
		User user = customUserDetailsService.getUserDetails(username);

		UserResponse userResponse = new UserResponse(user.getId(),user.getName(),user.getUsername());
		
        response.put("user", userResponse);
        response.put("authenticated", true);

        return response;
	}
	
}


com.spring.security.entities  =>  LoginRequest.java


package com.spring.security.entities;


public class LoginRequest {

	private String username;
	private String password;
	private boolean rememberMe;
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
	public boolean isRememberMe() {
		return rememberMe;
	}
	public void setRememberMe(boolean rememberMe) {
		this.rememberMe = rememberMe;
	}
	@Override
	public String toString() {
		return "LoginRequest [username=" + username + ", password=" + password + ", rememberMe=" + rememberMe + "]";
	}
	public LoginRequest() {
		super();
		// TODO Auto-generated constructor stub
	}
	public LoginRequest(String username, String password, boolean rememberMe) {
		super();
		this.username = username;
		this.password = password;
		this.rememberMe = rememberMe;
	}
	
	
}


com.spring.security.entities  =>  PersistentLogin.java


package com.spring.security.entities;

import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;

@Entity

@Table(name = "persistent_logins")

public class PersistentLogin {

	 	@Id
	    private String series;
	    
	    @Column(nullable = false)
	    private String username;
	    
	    @Column(nullable = false)
	    private String token;
	    
	    @Temporal(TemporalType.TIMESTAMP)
	    private Date lastUsed;

		public String getSeries() {
			return series;
		}

		public void setSeries(String series) {
			this.series = series;
		}

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getToken() {
			return token;
		}

		public void setToken(String token) {
			this.token = token;
		}

		public Date getLastUsed() {
			return lastUsed;
		}

		public void setLastUsed(Date lastUsed) {
			this.lastUsed = lastUsed;
		}

		@Override
		public String toString() {
			return "PersistentLogin [series=" + series + ", username=" + username + ", token=" + token + ", lastUsed="
					+ lastUsed + "]";
		}

		public PersistentLogin(String series, String username, String token, Date lastUsed) {
			super();
			this.series = series;
			this.username = username;
			this.token = token;
			this.lastUsed = lastUsed;
		}

		public PersistentLogin() {
			super();
			// TODO Auto-generated constructor stub
		}
	    
	    
}


com.spring.security.entities  =>  User.java


package com.spring.security.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity

public class User {

	@Id
	private int id;
	private String name;
	private String username;
	private String password;
	private String role;
	private Boolean enabled;
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
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
	public Boolean getEnabled() {
		return enabled;
	}
	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	@Override
	public String toString() {
		return "Login [id=" + id + ", name=" + name + ", username=" + username + ", password=" + password + ", role="
				+ role + ", enabled=" + enabled + "]";
	}
	
}


com.spring.security.entities  =>  UserResponse.java


package com.spring.security.entities;

public class UserResponse {

	private int id;
	private String name;
	private String username;
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public UserResponse(int id, String name, String username) {
		super();
		this.id = id;
		this.name = name;
		this.username = username;
	}
	public UserResponse() {
		super();
		// TODO Auto-generated constructor stub
	}
	@Override
	public String toString() {
		return "UserResponse [id=" + id + ", name=" + name + ", username=" + username + "]";
	}
	
	
}


com.spring.security.repository  =>  UserRepository.java

package com.spring.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.spring.security.entities.User;

@Repository

public interface UserRepository extends JpaRepository<User, Integer> {
	public User findByUsername(String username);
}



com.spring.security.service  =>  CustomUserDetailsService.java


package com.spring.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.spring.security.entities.User;
import com.spring.security.repository.UserRepository;
import com.spring.security.userdetails.CustomUserDetails;


@Service

public class CustomUserDetailsService implements UserDetailsService {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		User user = userRepository.findByUsername(username);
		if(user==null) {
			throw new UsernameNotFoundException("User Not Found !!!");
		}
		
		return new CustomUserDetails(user);
	}
	
	public User saveUser(User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return this.userRepository.save(user);
	}
	
	public User getUserDetails(String username) {
		return userRepository.findByUsername(username);
	}

}


com.spring.security.userDetails  =>  CustomUserDetails.java


package com.spring.security.userdetails;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.spring.security.entities.User;


public class CustomUserDetails implements UserDetails{
	
	private User user;
	
	public CustomUserDetails(User user) {
		super();
		this.user = user;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		System.out.println(this.user.getRole());
		return Collections.singleton(new SimpleGrantedAuthority("ROLE_"+user.getRole()));
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}



Application.properties 


spring.application.name=SpringSecurityWithAngular

spring.datasource.url = jdbc:mysql://localhost:3306/loginWithSpringSecurity
spring.datasource.username = root
spring.datasource.password = Mitra@123
spring.datasource.driver-class-name = com.mysql.cj.jdbc.Driver

spring.jpa.hibernate.ddl-auto=update

spring.jpa.properties.hiberate.show_sql = true
spring.jpa.properties.hiberate.format_sql = true


server.port=9898




Pom.xml => Dependencies ---  


<dependencies>
	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-data-jpa</artifactId>
	</dependency>
	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-security</artifactId>
	</dependency>
	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-web</artifactId>
	</dependency>
	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-devtools</artifactId>
		<scope>runtime</scope>
		<optional>true</optional>
	</dependency>
	<dependency>
		<groupId>com.mysql</groupId>
		<artifactId>mysql-connector-j</artifactId>
		<scope>runtime</scope>
	</dependency>
	<dependency>
		<groupId>org.projectlombok</groupId>
		<artifactId>lombok</artifactId>
		<optional>true</optional>
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
</dependencies>
