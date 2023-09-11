package com.redmath.transaction;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@EnableJpaRepositories
public interface TransactionRepository extends JpaRepository<Transaction, Long> {
    @Query(value = "SELECT * FROM Transaction WHERE account_id = ?", nativeQuery = true)
    Optional<List<Transaction>> findTransactionByAccountId(Long accountId);
//    @Query(value = "DELETE FROM Transaction WHERE account_id = ?", nativeQuery = true)
//    void deleteByAccountId(Long accountId);

    @Modifying
    @Query(value = "DELETE FROM Transaction WHERE account_id = :account_id", nativeQuery = true)
    void deleteByAccountId(@Param("account_id") Long account_id);
}
