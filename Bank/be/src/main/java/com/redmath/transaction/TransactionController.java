package com.redmath.transaction;

import com.redmath.balance.Balance;
import com.redmath.balance.BalanceService;
import com.redmath.basic.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/transaction")
@CrossOrigin
public class TransactionController {
    @Autowired
    private final TransactionService service;

    public TransactionController(TransactionService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<Transaction>> findAll() {
        List<Transaction> transactions = service.findAll();
        if (transactions.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(transactions);
    }

    @GetMapping("/{account_id}")
    @PreAuthorize("hasAuthority('ACCOUNT_HOLDER')")
    public ResponseEntity<List<Transaction>> findTransactionByAccountId(@PathVariable Long account_id){
        Optional<List<Transaction>> transaction = service.findTransactionByAccountId(account_id);
        if (transaction.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(transaction.get());
    }
    @PreAuthorize("hasAuthority('ACCOUNT_HOLDER')")
    @PostMapping
    public ResponseEntity<ApiResponse<Transaction>> MakeTransaction(@RequestBody Transaction transaction) {
        System.out.println(transaction.getAccount_id());
        System.out.println(transaction.getAmount());
        System.out.println(transaction.getId());
        System.out.println(transaction.getDB_CR());
        Optional< Transaction> created = service.MakeTransaction(transaction);
        if (created != null) {
            return ResponseEntity.ok(ApiResponse.of(created.get()));
        }
        return ResponseEntity.status(HttpStatus.CONFLICT).build();
    }

}