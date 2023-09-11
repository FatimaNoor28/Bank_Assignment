package com.redmath.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query(value = "select * from users where user_name = ?", nativeQuery = true)
    User findByUserName (String username);

    @Query(value = "SELECT * FROM users WHERE user_name = ?1 AND password = ?2", nativeQuery = true)
    User findByUserNameAndPassword (String username, String password);
}