package com.redmath.users;


import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.Console;
import java.util.List;
import java.util.Optional;

@Service
public class UserService implements UserDetailsService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository repository, PasswordEncoder passwordEncoder){this.repository = repository; this.passwordEncoder = passwordEncoder; }

    public List<User> findAll(){
        return repository.findAll();
    }

    public User findByUserName(String user_name){
        return repository.findByUserName(user_name);
    }
    public Optional<User> findById(Long id){
        return repository.findById(id);
    }

    public String getRole(String userName){
        User user = findByUserName(userName);
        String role = user.getRoles();
        System.out.println(role);
        return role;
    }
    public User create(String name, String password){
        User user = new User();
        user.setUserName(name);
        // Hash the password before saving it to the database
        String hashedPassword = passwordEncoder.encode(password);
        user.setPassword(hashedPassword);
        user.setRoles("ADMIN");
        return repository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        User user = findByUserName(name);
        //Account account = repository.findByName(name);
        if (user == null) {
            throw new UsernameNotFoundException("Invalid user: " + name);
        }
        System.out.println("Logged In Successfull");
        return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassword(), true,
                true, true,true,
                AuthorityUtils.commaSeparatedStringToAuthorityList(user.getRoles()));
    }
}