package com.redmath.balance;

import com.redmath.account.Account;
import com.redmath.account.AccountService;
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
@RequestMapping("/api/v1/balance")
@CrossOrigin
public class BalanceController {
    @Autowired
    private final BalanceService service;

    public BalanceController(BalanceService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<Balance>> findAll() {

        List<Balance> balances = service.findAll();
        if (balances.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(balances);
    }
    @GetMapping("/{account_id}")
    @PreAuthorize("hasAuthority('ACCOUNT_HOLDER')")
    public ResponseEntity<Balance> getBalanceByAccountId(@PathVariable Long account_id){
        Optional<Balance> balance = service.findBalanceByAccountId(account_id);
        if (balance.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(balance.get());
    }

    @PreAuthorize("hasAuthority('ACCOUNT_HOLDER')")
    @PostMapping()
    public ResponseEntity<ApiResponse<Balance>> AddBalance(@RequestBody Balance balance) {
        System.out.println(balance.getAccount_id());
        System.out.println(balance.getAmount());
        System.out.println(balance.getDB_CR());

        Balance created = service.AddBalance(balance);
        if (created != null) {
            return ResponseEntity.ok(ApiResponse.of(created));
        }
        return ResponseEntity.status(HttpStatus.CONFLICT).build();
    }

//    @PutMapping("/{id}")
//    @PreAuthorize("hasAuthority('ACCOUNT_HOLDER')")
//    public void update(@RequestBody Balance balance){
//        service.update(balance);
//    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ACCOUNT_HOLDER')")
    public void delete(@PathVariable Long id){
        service.delete(id);
    }


}