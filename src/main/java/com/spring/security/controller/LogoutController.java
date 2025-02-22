package com.spring.security.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

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

//        // Invalidate session
//        request.getSession().invalidate();
//        
//        // Clear Security Context
//        SecurityContextHolder.clearContext();
//
//        // Remove Cookies
//        Cookie cookie = new Cookie("JSESSIONID", null);
//        cookie.setPath("/");
//        cookie.setHttpOnly(true);
//        cookie.setMaxAge(0);
//        response.addCookie(cookie);

        // Send response
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
