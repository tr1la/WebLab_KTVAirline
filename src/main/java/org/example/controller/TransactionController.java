package org.example.controller;

import org.example.constant.TransactionStatusEnum;
import org.example.entity.Transaction;
import org.example.service.TransactionService;
import org.example.serviceImpl.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.*;

import java.sql.Date;
import java.util.List;

@RestController
@RequestMapping("/api/v1/transaction")
public class TransactionController {
    @Autowired
    TransactionService transactionService;

    @GetMapping(value = "/conditions")
    public ResponseEntity<?> getByConditions(@RequestParam String flightName
            , @RequestParam Date dateFrom, @RequestParam Date dateTo, @RequestParam TransactionStatusEnum status
            , @RequestParam Integer pageNum, @RequestParam Integer pageSize) {
        try {
            Pageable pageable = PageRequest.of(pageNum, pageSize);
            List<Transaction> transactionList = transactionService
                    .findByConditions(flightName, dateFrom, dateTo, status, pageable);
            if (ObjectUtils.isEmpty(transactionList)) {
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {
                return ResponseEntity.ok().body(transactionList);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @GetMapping(value = "/all")
    public ResponseEntity<?> getAll(@RequestParam Integer pageNum
            , @RequestParam Integer pageSize) {
        try {
            Pageable pageable = PageRequest.of(pageNum, pageSize);
            List<Transaction> transactionList = transactionService
                    .findAll(pageable);
            if (ObjectUtils.isEmpty(transactionList)) {
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {
                return ResponseEntity.ok().body(transactionList);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @GetMapping(value = "/id")
    public ResponseEntity<?> getById(@RequestParam Integer id) {
        try {
            Transaction transaction = transactionService.findById(id);
            if (ObjectUtils.isEmpty(transaction)) {
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {
                return ResponseEntity.ok().body(transaction);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @PostMapping
    public ResponseEntity<?> saveTransaction(@RequestBody Transaction transaction) {
        try {
            transaction.setId(null);
            Transaction savedTransaction = transactionService.save(transaction);
            if (ObjectUtils.isEmpty(transaction)) {
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {
                return ResponseEntity.ok().body(savedTransaction);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @PutMapping
    public ResponseEntity<?> editTransaction(@RequestBody Transaction transaction) {
        try {
            Transaction savedTransaction = transactionService.save(transaction);
            if (ObjectUtils.isEmpty(transaction)) {
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {
                return ResponseEntity.ok().body(savedTransaction);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @PutMapping(value = "/list")
    public ResponseEntity<?> editTransactions(@RequestBody List<Transaction> transactions) {
        try {
            for(Transaction transaction : transactions){
                Transaction savedTransaction = transactionService.save(transaction);
            }
            return ResponseEntity.ok().body("Edited");
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @DeleteMapping
    public ResponseEntity<?> deleteTransaction(@RequestParam Integer id) {
        try {
            if (ObjectUtils.isEmpty(transactionService.findById(id))) {
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {
                transactionService.delete(id);
                return ResponseEntity.ok().body("Deleted");
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @GetMapping(value = "/status")
    public ResponseEntity<?> getByStatus(@RequestParam TransactionStatusEnum statusEnum) {
        try {
            List<Transaction> transaction = transactionService.findByStatus(statusEnum);
            if (ObjectUtils.isEmpty(transaction)) {
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {
                return ResponseEntity.ok().body(transaction);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @GetMapping(value = "/flight")
    public ResponseEntity<?> sendDelayNoti(@RequestParam Integer flightId) {
        try {
            List<Transaction> transactions = transactionService.findByFlightId(flightId);
            if (ObjectUtils.isEmpty(transactions)) {
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {               
                return ResponseEntity.ok().body(transactions);
            }
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }
}
