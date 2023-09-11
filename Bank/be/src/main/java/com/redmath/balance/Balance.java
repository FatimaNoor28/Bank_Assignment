package com.redmath.balance;
import java.time.LocalDate;
import java.util.Date;
import com.redmath.account.Account;
import jakarta.persistence.*;

@Entity(name = "Balance")
public class Balance {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "balance_id")
    private Long balance_id;
    @Column(name = "account_id")
    private Long account_id;
    private Long amount;

    private String db_CR;
    private LocalDate date;

    public Long getId() {
        return balance_id;
    }
    public Long getAccount_id() {
        return account_id;
    }
    public void setAccount_id(Long id) {
        this.account_id = id;
    }

    public void setId(Long BalanceId) {
        this.balance_id = BalanceId;
    }

    public Long getAmount() {
        return amount;
    }
    public void setAmount(Long amount) { this.amount = amount;    }

    public void setDB_CR(String db_cr) {
        this.db_CR = db_cr;
    }

    public String getDB_CR() { return db_CR;}

    public LocalDate getDate() {
        return date;
    }

    public void setDate(LocalDate Date) {
        this.date = Date;
    }
}
