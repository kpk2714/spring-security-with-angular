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
