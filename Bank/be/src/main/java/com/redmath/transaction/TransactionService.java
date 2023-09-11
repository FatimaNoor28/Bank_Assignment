package com.redmath.transaction;

import com.redmath.balance.Balance;
import com.redmath.balance.BalanceService;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Service
public class TransactionService {
    private final TransactionRepository repository;
    private final BalanceService balanceService;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public TransactionService(TransactionRepository repository, BalanceService service){
        this.balanceService = service;
        this.repository = repository;}

    public List<Transaction> findAll(){return repository.findAll();}

    public Optional<List<Transaction>> findTransactionByAccountId(Long accountId){
        Optional<List<Transaction>> transactions = Optional.empty();
        transactions = repository.findTransactionByAccountId(accountId);
        return transactions;
    }

    public Optional<Transaction> MakeTransaction(Transaction transaction){
        Optional<Balance> balance = balanceService.findBalanceByAccountId(transaction.getAccount_id());
        if(balance.isEmpty()) {
            System.out.println("balance not found");
            logger.warn("Balance not found for account_id: " + transaction.getAccount_id());
            return Optional.empty();
        }
        balance.ifPresent(b -> balanceService.add_subtract_balance(b, transaction.getDB_CR(), transaction.getAmount()));
        transaction.setDate(LocalDate.now());
        Transaction savedTransaction = repository.save(transaction);
        System.out.println("Balance found and transaction created");


        return Optional.of(savedTransaction);
    }
    //Long amount = balanceValue.getAmount();
//        if(transaction.getDB_CR().equals("db")) {
//            System.out.println("DB pressed");
//            if (amount >= transaction.getAmount()) {
//                balanceService.DeductAmount(balanceValue.getId(), transaction.getAmount());
//                transaction.setDate(LocalDate.now());
//                return Optional.of(repository.save(transaction));
//            }
//        } else if (transaction.getDB_CR().equals("cr")) {
//            amount= amount+ transaction.getAmount();
//            balanceValue.setAmount(amount);
//            balanceService.AddBalance(balanceValue);
//            transaction.setDate(LocalDate.now());
//            return Optional.of(repository.save(transaction));
//        }
//        else
//            System.out.println("DB/CR incorrect indicator");


    @Transactional
    public void deleteByAccountId(Long accountId){

        if(!repository.findTransactionByAccountId(accountId).isEmpty())
            repository.deleteByAccountId(accountId);
    }
}
