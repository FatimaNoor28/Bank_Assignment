package com.redmath.admins;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

//import java.time.LocalDateTime;

@Entity(name = "Admins")
public class Admin {

    @Id
    private Long user_id;
    private String user_name;
    private String password;
    private String role;

    public Long getId() {
        return user_id;
    }

    public void setId(Long id) {
        this.user_id = id;
    }

    public String getUserName() {
        return user_name;
    }

    public void setUserName(String userName) {
        this.user_name = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRoles() {
        return role;
    }

    public void setRoles(String roles) {
        this.role = roles;
    }
}