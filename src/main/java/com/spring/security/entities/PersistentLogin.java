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
