package org.example.serviceImpl;

import org.example.constant.PromotionDiscountType;
import org.example.constant.SeatType;
import org.example.entity.Promotion;
import org.example.repository.PromotionRepository;
import org.example.service.PromotionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;

@Service
public class PromotionServiceImpl implements PromotionService {
    private static final Logger logger = LoggerFactory.getLogger(PromotionServiceImpl.class);

    @Autowired
    PromotionRepository promotionRepository;

    @Value("${app.promotion-import-dir:imports/promotions}")
    private String importDir;

    @Override
    public List<Promotion> findAll(Pageable pageable) {
        return promotionRepository.findByIsDeletedFalse(pageable).getContent();
    }

    @Override
    public List<Promotion> findByCode(String code, Pageable pageable) {
        return promotionRepository.findByCodeContainsAndIsDeletedFalse(code, pageable).getContent();
    }

    @Override
    public List<Promotion> findByTitle(String title, Pageable pageable) {
        return promotionRepository.findByTitleContainsAndIsDeletedFalse(title, pageable).getContent();
    }

    @Override
    public List<Promotion> findByActive(Boolean active, Pageable pageable) {
        return promotionRepository.findByActiveAndIsDeletedFalse(active, pageable).getContent();
    }

    @Override
    public List<Promotion> findBySeatType(SeatType seatType, Pageable pageable) {
        return promotionRepository.findBySeatTypeAndIsDeletedFalse(seatType, pageable).getContent();
    }

    @Override
    public Promotion findById(Integer id) {
        return promotionRepository.findByIdAndIsDeletedFalse(id);
    }

    @Override
    public Promotion save(Promotion promotion) {
        applyDefaults(promotion);
        return promotionRepository.save(promotion);
    }

    @Override
    public Promotion importPromotion(Promotion promotion) {
        Promotion existingPromotion = null;
        if (promotion.getCode() != null) {
            existingPromotion = promotionRepository.findByCodeAndIsDeletedFalse(promotion.getCode());
        }

        if (existingPromotion != null) {
            promotion.setId(existingPromotion.getId());
            promotion.setCreateBy(existingPromotion.getCreateBy());
            promotion.setCreateDate(existingPromotion.getCreateDate());
            promotion.setDeleted(existingPromotion.isDeleted());
        }

        applyDefaults(promotion);
        return promotionRepository.save(promotion);
    }

    @Override
    public Map<String, String> queuePromotionXml(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Promotion XML file is required");
        }

        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.isBlank()) {
            throw new IllegalArgumentException("Filename is required");
        }

        String safeFilename = Paths.get(originalFilename).getFileName().toString();
        if (!safeFilename.toLowerCase().endsWith(".xml")) {
            throw new IllegalArgumentException("Only XML promotion files are allowed");
        }

        Path promotionDir = Paths.get(importDir).toAbsolutePath().normalize();
        Files.createDirectories(promotionDir);

        Path destination = promotionDir.resolve(safeFilename).normalize();
        Path uploadingFile = promotionDir.resolve(safeFilename + ".uploading").normalize();

        file.transferTo(uploadingFile.toFile());
        Files.move(uploadingFile, destination, StandardCopyOption.REPLACE_EXISTING);

        return Map.of(
                "status", "QUEUED",
                "fileName", safeFilename,
                "path", destination.toString()
        );
    }

    @Scheduled(initialDelayString = "${app.promotion-import-initial-delay-ms:3000}", fixedDelayString = "${app.promotion-import-fixed-delay-ms:6000}")
    public void importPromotionXmlFiles() {
        Path promotionDir = Paths.get(importDir).toAbsolutePath().normalize();

        try {
            Files.createDirectories(promotionDir);
        } catch (IOException e) {
            logger.warn("Could not create promotion import directory {}", promotionDir, e);
            return;
        }

        try (DirectoryStream<Path> files = Files.newDirectoryStream(promotionDir, "*.{xml,XML}")) {
            for (Path xmlFile : files) {
                importPromotionXml(xmlFile);
            }
        } catch (IOException e) {
            logger.warn("Could not scan promotion import directory {}", promotionDir, e);
        }
    }

    private void importPromotionXml(Path xmlFile) {
        try (XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(Files.newInputStream(xmlFile)))) {
            Object decodedObject = decoder.readObject();
            if (decodedObject instanceof Promotion promotion) {
                Promotion savedPromotion = importPromotion(promotion);
                logger.info("Imported promotion XML {} as promotion {}", xmlFile.getFileName(), savedPromotion.getCode());
            } else {
                logger.info("Imported promotion XML {} as {}", xmlFile.getFileName(), decodedObject);
            }
            moveToProcessed(xmlFile);
        } catch (Exception e) {
            logger.warn("Failed to import promotion XML {}", xmlFile.getFileName(), e);
        }
    }

    private void moveToProcessed(Path xmlFile) throws IOException {
        Path processedDir = xmlFile.getParent().resolve("processed");
        Files.createDirectories(processedDir);
        Files.move(xmlFile, processedDir.resolve(xmlFile.getFileName()), StandardCopyOption.REPLACE_EXISTING);
    }

    @Override
    public void delete(Integer id) {
        Promotion promotion = promotionRepository.findByIdAndIsDeletedFalse(id);
        promotion.setDeleted(true);
        promotionRepository.save(promotion);
    }

    private void applyDefaults(Promotion promotion) {
        if (promotion.getActive() == null) {
            promotion.setActive(true);
        }
        if (promotion.getUsedCount() == null) {
            promotion.setUsedCount(0);
        }
        if (promotion.getDiscountType() == null) {
            promotion.setDiscountType(PromotionDiscountType.PERCENTAGE);
        }
        if (promotion.getDiscountValue() == null) {
            promotion.setDiscountValue(BigDecimal.ZERO);
        }
    }
}
