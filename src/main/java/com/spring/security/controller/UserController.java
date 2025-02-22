package com.spring.security.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class UserController {
	
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
	
}
