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
