package com.redmath.account;
import com.redmath.balance.Balance;
import com.redmath.transaction.Transaction;

import java.awt.font.OpenType;
import java.util.List;
import java.util.Optional;

public class AccountDetailsResponse {
    private Account account;
    private Optional<Balance> balance ;
    private Optional<Transaction> transaction;

    public AccountDetailsResponse() {
        // Initialize lists if needed
        this.account = null;
        this.balance = Optional.empty();
        this.transaction = Optional.empty();
    }

    // Getters and setters

    public Account getAccount(){return account;}

    public void setAccount(Account account){this.account = account; }

    public Optional<Balance> getBalance() {
        return balance;
    }

    public void setBalance(Optional<Balance> balance) {
        this.balance = balance;
    }

    public Optional<Transaction> getTransaction() {
        return transaction;
    }

    public void setTransaction(Optional<Transaction> transaction) {
        this.transaction = transaction;
    }

}
