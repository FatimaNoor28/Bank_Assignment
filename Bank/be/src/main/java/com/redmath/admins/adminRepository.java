package com.redmath.admins;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface adminRepository extends JpaRepository<Admin, Long> {
    @Query(value = "select * from Admins where user_name = ?", nativeQuery = true)
    Admin findByUserName (String username);
}