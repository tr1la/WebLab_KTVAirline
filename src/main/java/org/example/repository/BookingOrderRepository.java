package org.example.repository;

import org.example.entity.BookingOrder;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.math.BigDecimal;

public interface BookingOrderRepository extends JpaRepository<BookingOrder, Integer> {
    public BookingOrder findByIdAndIsDeletedFalse(Integer id);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            update `booking_order`
            set DISCOUNT_AMOUNT = DISCOUNT_AMOUNT + :discountAmount,
                TOTAL_AMOUNT = greatest(TOTAL_AMOUNT - :discountAmount, 0)
            where ID = :id and IS_DELETED = false
            """, nativeQuery = true)
    public int applyPromotionDiscount(@Param("id") Integer id, @Param("discountAmount") BigDecimal discountAmount);
    /*
     * VULNERABLE RACE CONDITION SINK: this atomic-looking update still lets
     * concurrent requests stack the same promotion, because it subtracts from the
     * current TOTAL_AMOUNT and has no unique applied-promotion row to reject a
     * duplicate code for the same order.
     *
     * FIXED CODE:
     *
     * package org.example.repository;
     *
     * import jakarta.persistence.LockModeType;
     * import org.example.entity.BookingOrder;
     * import org.springframework.data.jpa.repository.JpaRepository;
     * import org.springframework.data.jpa.repository.Lock;
     * import org.springframework.data.jpa.repository.Query;
     * import org.springframework.data.repository.query.Param;
     *
     * public interface BookingOrderRepository extends JpaRepository<BookingOrder, Integer> {
     *     BookingOrder findByIdAndIsDeletedFalse(Integer id);
     *
     *     @Lock(LockModeType.PESSIMISTIC_WRITE)
     *     @Query("select o from BookingOrder o where o.id = :id and o.isDeleted = false")
     *     BookingOrder findByIdAndIsDeletedFalseForUpdate(@Param("id") Integer id);
     * }
     *
     * Remove the vulnerable applyPromotionDiscount(...) method entirely. The fixed
     * applyPromotion flow must lock the BookingOrder with
     * findByIdAndIsDeletedFalseForUpdate(...), insert or read unique
     * BOOKING_ORDER_PROMOTION rows, then save:
     *
     * order.setDiscountAmount(totalDiscountFromAppliedPromotions);
     * order.setTotalAmount(order.getSubtotal()
     *         .subtract(totalDiscountFromAppliedPromotions)
     *         .max(BigDecimal.ZERO));
     *
     * That recalculates the final price from SUBTOTAL instead of decrementing
     * the persisted TOTAL_AMOUNT once per concurrent request.
     */
}
