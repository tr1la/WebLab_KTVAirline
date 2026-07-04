package org.example.entity;

import jakarta.persistence.*;
import lombok.*;
import org.example.constant.BookingOrderStatus;

import java.math.BigDecimal;
import java.util.Date;

@Table(name = "BOOKING_ORDER")
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class BookingOrder extends BaseObject {
    @ManyToOne
    @JoinColumn(name = "USER_ID", nullable = false)
    private User user;

    @Column(name = "TRANSACTION_IDS", nullable = false, length = 1000)
    private String transactionIds;

    @Enumerated(EnumType.STRING)
    @Column(name = "STATUS", nullable = false)
    private BookingOrderStatus status;

    @Column(name = "SUBTOTAL", nullable = false, precision = 12, scale = 2)
    private BigDecimal subtotal;

    @Column(name = "DISCOUNT_AMOUNT", nullable = false, precision = 12, scale = 2)
    private BigDecimal discountAmount;

    @Column(name = "TOTAL_AMOUNT", nullable = false, precision = 12, scale = 2)
    private BigDecimal totalAmount;

    @Column(name = "APPLIED_PROMOTION_CODES", length = 1000)
    private String appliedPromotionCodes;
    /*
     * FIXED CODE:
     *
     * // Do not use APPLIED_PROMOTION_CODES as the source of truth for duplicate
     * // prevention. Keep it only as an optional display snapshot, or remove it and
     * // read applied codes through the unique BOOKING_ORDER_PROMOTION relation.
     *
     * @OneToMany(mappedBy = "order")
     * private List<BookingOrderPromotion> appliedPromotions = new ArrayList<>();
     */

    @Column(name = "HOLD_EXPIRES_AT")
    private Date holdExpiresAt;

    @Column(name = "QR_CODE")
    private String qrCode;
}
