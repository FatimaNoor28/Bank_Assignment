package com.redmath.account;

import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@EnableJpaRepositories
public interface AccountRepository extends JpaRepository<Account, Long> {
    Account findByName(String name);

//    @Query(value = "DELETE FROM Account WHERE account_id = :accountId", nativeQuery = true)
    void deleteById( Long accountId);
    Optional<Account> findAccountByNameAndPassword(String name, String password);
}
