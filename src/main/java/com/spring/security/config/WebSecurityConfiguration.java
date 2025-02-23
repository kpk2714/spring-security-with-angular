package com.spring.security.config;

import java.util.List;

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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration{
	
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
										  //.invalidateHttpSession(true)
										  //.deleteCookies("JSESSIONID", "remember-me")
										  .permitAll()
								  )
								  .sessionManagement( session -> session
										  .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
								   );
								 
		return http.build();
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