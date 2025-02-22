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