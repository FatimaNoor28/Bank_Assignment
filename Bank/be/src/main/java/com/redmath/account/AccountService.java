package com.redmath.account;
import com.redmath.balance.Balance;
import com.redmath.balance.BalanceService;
import com.redmath.transaction.Transaction;
import com.redmath.transaction.TransactionService;
import com.redmath.users.User;
import com.redmath.account.LoginMessage;

//import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import com.redmath.users.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@Service
public class AccountService //implements UserDetailsService
{
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final AccountRepository repository;
    private final UserService userService;
    private final BalanceService balanceService;
    private final TransactionService transactionService;

    @Autowired
    private PasswordEncoder passwordEncoder;
    public AccountService(AccountRepository repository, UserService userService, BalanceService balanceService, TransactionService transactionService)
    {
        this.repository = repository;
        this.userService = userService;
        this.balanceService = balanceService;
        this.transactionService = transactionService;
    }


    public List<Account> findAll(){
        return repository.findAll();
    }


    public Optional<Account> findAccountByNameAndPassword(String username, String password){
        return repository.findAccountByNameAndPassword(username, password);
    }
//    public Optional<AccountDetailsResponse> findById(Long id){
//
//        Optional<Account> account= repository.findById(id);
//        if (account.isEmpty()) {
//            return Optional.empty();
//        }
//            Optional<Balance> balance = balanceService.findBalanceByAccountId(account.get().getId());
//            Optional<List<Transaction>> transactions = transactionService.findTransactionByAccountId(account.get().getId());
//
//        AccountDetailsResponse response = new AccountDetailsResponse();
//
//        response.setAccount(account.get());
//        response.setBalance(balance);
//        response.setTransaction(transactions);
//        logger.warn("Not Authorized!!");
//        return Optional.of(response);
//    }


    public Account create(Account account){
        if (account.getId() != null && repository.existsById(account.getId())) {
            logger.warn("News with id {} already exists", account.getId());
            return null;
        }
        String encodedPassword = passwordEncoder.encode(account.getPassword());
        userService.create(account.getName(), encodedPassword);
        account.setPassword(encodedPassword);
        return repository.save(account);
    }

    public Optional<Void> update(Account account){
        if(account.getId()!=null && repository.existsById(account.getId())){
            repository.save(account);
            return Optional.empty();
        }
        return null;
    }

    public Optional<Void> delete(Long id){
        if (repository.existsById(id)) {
            Optional<Account> accountToBeDeleted = repository.findById(id);
            repository.deleteById(id);

            transactionService.deleteByAccountId(id);
            balanceService.deleteByAccountId(id);

            return Optional.empty();
        }
        return null;
    }
}
