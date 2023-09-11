package com.redmath.admins;


import org.springframework.stereotype.Service;

@Service
public class adminService {
    private final adminRepository repository;

    public adminService(adminRepository repository){this.repository = repository; }

    public Admin findByUserName(String user_name){
        return repository.findByUserName(user_name);
    }
}