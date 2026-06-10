package org.example.repository;

import org.example.constant.TransactionStatusEnum;
import org.example.entity.Transaction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.sql.Date;
import java.util.List;

public interface TransactionRepository extends JpaRepository<Transaction, String> {
    public List<Transaction> findByFlightNameContainsAndAndCreateDateBetweenAndStatusAndIsDeletedFalse(String flightName, Date dateFrom, Date dateTo,
                                                                         TransactionStatusEnum status, Pageable pageable);

    public List<Transaction> findByStatusAndIsDeletedFalse(TransactionStatusEnum status);

    public Page<Transaction> findByIsDeletedFalse(Pageable pageable);

    public List<Transaction> findByFlightIdAndIsDeletedFalse(Integer id);

    public Transaction findByIdAndIsDeletedFalse(Integer id);
}
