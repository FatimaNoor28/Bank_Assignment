package com.redmath.balance;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
//@EnableJpaRepositories
public interface BalanceRepository extends JpaRepository<Balance ,Long>{
//    @Query(value = "SELECT * FROM Balance WHERE account_id = ?", nativeQuery = true)
//    Optional<Balance> findBalanceByAccountId(Long accountId);


    @Query(value = "SELECT * FROM Balance WHERE account_id = :account_id", nativeQuery = true)
    Optional<Balance> findBalanceByAccountId(@Param("account_id")Long account_id);

//    @Query(value = "DELETE FROM Balance WHERE account_id = ?", nativeQuery = true)
//    void deleteByAccountId(Long account_id);


    @Modifying
    @Query(value = "DELETE FROM Balance WHERE account_id = :account_id", nativeQuery = true)
    void deleteByAccountId(@Param("account_id") Long account_id);

}
