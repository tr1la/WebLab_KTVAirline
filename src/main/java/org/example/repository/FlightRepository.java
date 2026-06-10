package org.example.repository;

import org.example.constant.FlightStatus;
import org.example.entity.Flight;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface FlightRepository extends JpaRepository<Flight, String> {
    List<Flight> findByIsDeletedFalse(Pageable pageable);

    Flight findByIdAndIsDeletedFalse(Integer id);

    List<Flight> findByStatusAndIsDeletedFalse(FlightStatus statusEnum);

    List<Flight> findByIsDeletedFalseAndNameContainsAndStartTimeBetweenAndDepartureContainsAndArrivalContains
            (String flightName, LocalDateTime dateFrom, LocalDateTime dateTo, String departure, String arrival, Pageable pageable);

    @Query("SELECT f FROM Flight f WHERE f.isDeleted = false " +
           "AND (LOWER(f.name) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(f.departureCode) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(f.arrivalCode) LIKE LOWER(CONCAT('%', :searchTerm, '%'))) " +
           "AND f.startTime BETWEEN :dateFrom AND :dateTo " +
           "AND LOWER(f.departure) LIKE LOWER(CONCAT('%', :departure, '%')) " +
           "AND LOWER(f.arrival) LIKE LOWER(CONCAT('%', :arrival, '%'))")
    List<Flight> searchFlights(
            @Param("searchTerm") String searchTerm,
            @Param("dateFrom") LocalDateTime dateFrom,
            @Param("dateTo") LocalDateTime dateTo,
            @Param("departure") String departure,
            @Param("arrival") String arrival,
            Pageable pageable);
}
