package com.redmath.users;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.event.*;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;

import java.io.Console;
import java.util.List;
import java.util.Optional;

@Service
public class UserService implements UserDetailsService , ApplicationListener<AbstractAuthenticationEvent> {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    @Lazy
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
        user.setPassword(passwordEncoder.encode(password));
        user.setRoles("ACCOUNT_HOLDER");
        return repository.save(user);
    }

    @Cacheable("users")
    public UserDetails loadUserByUsername(String jti, String userName) throws UsernameNotFoundException {
        return loadUserByUsername(userName);
    }
    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        User user = findByUserName(name);
        if (user == null) {
            throw new UsernameNotFoundException("Invalid user: " + name);
        }
        System.out.println("Logged In Successfull");
        return new org.springframework.security.core.userdetails.User(user.getUserName(), user.getPassword(), true,
                true, true,true,
                AuthorityUtils.commaSeparatedStringToAuthorityList(user.getRoles()));
    }

    @Override
    public void onApplicationEvent(AbstractAuthenticationEvent event) {
        logger.debug("::security:: authentication event: {}", event);
        if (event instanceof AuthenticationSuccessEvent success) {
            logger.info("::security:: authentication successful for user: {}", success.getAuthentication().getName());
        } else if (event instanceof InteractiveAuthenticationSuccessEvent success) {
            logger.info("::security:: login successful for user: {}", success.getAuthentication().getName());
        } else if (event instanceof AbstractAuthenticationFailureEvent failure) {
            logger.warn("::security:: authentication failed for user: {}, reason: {}",
                    failure.getAuthentication().getName(), String.valueOf(failure.getException()));
        } else {
            logger.info("::security:: authentication event for user: {}, {}", event.getAuthentication().getName(),
                    event);
        }
    }
}