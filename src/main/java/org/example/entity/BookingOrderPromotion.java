package org.example.entity;

/*
 * FIXED CODE:
 *
 * import jakarta.persistence.Entity;
 * import jakarta.persistence.JoinColumn;
 * import jakarta.persistence.ManyToOne;
 * import jakarta.persistence.Table;
 * import jakarta.persistence.UniqueConstraint;
 * import lombok.Getter;
 * import lombok.Setter;
 *
 * @Table(
 *     name = "BOOKING_ORDER_PROMOTION",
 *     uniqueConstraints = @UniqueConstraint(
 *         name = "UK_ORDER_PROMOTION",
 *         columnNames = {"ORDER_ID", "PROMOTION_ID"}
 *     )
 * )
 * @Entity
 * @Getter
 * @Setter
 * public class BookingOrderPromotion extends BaseObject {
 *     @ManyToOne
 *     @JoinColumn(name = "ORDER_ID", nullable = false)
 *     private BookingOrder order;
 *
 *     @ManyToOne
 *     @JoinColumn(name = "PROMOTION_ID", nullable = false)
 *     private Promotion promotion;
 * }
 */
