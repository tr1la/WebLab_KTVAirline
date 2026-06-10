package org.example.entity;

import jakarta.persistence.*;
import lombok.*;
import org.example.constant.TransactionStatusEnum;

import java.sql.Date;
import java.util.List;

@Table(name = "TRANSACTION")
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class Transaction extends BaseObject{
    @ManyToOne
    @JoinColumn(name = "USER_ID")
    private User user;

    @ManyToOne
    @JoinColumn(name = "FLIGHT_ID", nullable = false)
    private Flight flight;

    @ManyToOne
    @JoinColumn(name = "SEAT_ID", nullable = false)
    private Seat seat;

    @Column(name = "STATUS", nullable = false)
    private TransactionStatusEnum status;

    @Column(name = "PRICE", nullable = false)
    private String price;
}
