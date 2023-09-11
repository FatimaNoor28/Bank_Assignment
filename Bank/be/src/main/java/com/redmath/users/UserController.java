package com.redmath.users;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
@CrossOrigin
public class UserController {
    @Autowired
    private final UserService service;

    public UserController(UserService service){this.service = service; }


    @GetMapping("/role/{userName}")
    public String getRole(@PathVariable("userName") String userName){
        System.out.println(userName);
        return service.getRole(userName);
    }
    @GetMapping
//    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<User>> findAll() {
        List<User> users = service.findAll();
        if (users.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(users);
    }
}
