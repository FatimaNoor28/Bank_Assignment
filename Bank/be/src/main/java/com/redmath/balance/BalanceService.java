package com.redmath.balance;

import com.redmath.account.AccountRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Service
public class BalanceService {
    private final BalanceRepository repository;

    public BalanceService(BalanceRepository repository){this.repository = repository; }

    public List<Balance> findAll(){return repository.findAll();}
    public Optional<Balance> findBalanceByAccountId(Long accountId){
//        Optional<List<Balance>> balances = Optional.empty();
        return repository.findBalanceByAccountId(accountId);
    }

    public Balance AddBalance(Balance balance){
        Optional<Balance> oldBalance = repository.findBalanceByAccountId(balance.getAccount_id());
        if(oldBalance.isEmpty())
        {
            System.out.println("service if part called");
            balance.setDate(LocalDate.now());
        }
        else{
            System.out.println("service else part called");
            Balance bal = oldBalance.get();
            Long amount = balance.getAmount()+ bal.getAmount();
            System.out.println("New Balance: "+amount);
            balance.setAmount(amount);
            balance.setDB_CR(balance.getDB_CR());
            balance.setDate(LocalDate.now());
        }
        return repository.save(balance);
    }

    public Balance add_subtract_balance(Balance balance, String db_cr, Long amount){

        if(db_cr.equals("db"))
            return DeductAmount(balance.getId(), amount);
        else if (db_cr.equals("cr")) {
            balance.setDB_CR(db_cr);
            balance.setAmount(balance.getAmount()+amount);
            return repository.save(balance);
        }
        return null;
    }
    public void delete(Long id){repository.deleteById(id); }
    @Transactional
    public void deleteByAccountId(Long accountId){
        if(!repository.findBalanceByAccountId(accountId).isEmpty())
            repository.deleteByAccountId(accountId);
    }

    public Balance DeductAmount(Long id ,Long amount){
        Optional<Balance> balance = repository.findById(id);
        balance.get().setAmount(balance.get().getAmount() - amount);
        return repository.save(balance.get());
    }
}
