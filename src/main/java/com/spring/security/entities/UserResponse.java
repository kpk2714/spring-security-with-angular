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
