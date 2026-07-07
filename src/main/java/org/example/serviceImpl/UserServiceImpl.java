package org.example.serviceImpl;

import org.example.entity.User;
import org.example.repository.UserRepository;
import org.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Value("${app.upload-dir:uploads}")
    private String uploadDir;

    private static final Set<String> BLOCKED_FILE_EXTENSIONS = Set.of(
            ".exe",
            ".bat",
            ".cmd",
            ".sh",
            ".jar",
            ".jsp",
            ".xml");
    private static final Pattern OBVIOUS_PARENT_TRAVERSAL = Pattern.compile("(^|/)\\.\\./(?!/)");
    /*
     * The regex above only catches a parent segment followed by a single slash.
     * It misses repeated separators such as "..//" before the filesystem resolves
     * them as normal path separators.
     *
     * FIXED CODE:
     *
     * private static final Pattern OBVIOUS_PARENT_TRAVERSAL =
     * Pattern.compile("(^|[\\\\/])\\.\\.(?:[\\\\/]+|$)");
     *
     *
     */

    @Override
    public Integer saveUser(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepository.save(user).getId();
    }

    @Override
    public Integer save(User user) {
        return userRepository.save(user).getId();
    }

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmailAndIsDeletedFalse(email);
    }

    @Override
    public User findById(Integer id) {
        return userRepository.findByIdAndIsDeletedFalse(id);
    }

    @Override
    public List<User> findAll(Pageable pageable) {
        return userRepository.findByIsDeletedFalse(pageable).getContent();
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmailAndIsDeletedFalse(email);
    }

    @Override
    public boolean existsById(Integer id) {
        return userRepository.existsByIdAndIsDeletedFalse(id);
    }

    @Override
    public void deletesById(Integer id) {
        User user = userRepository.findByIdAndIsDeletedFalse(id);
        user.setDeleted(true);
        userRepository.save(user);
    }

    @Override
    public User uploadAvatar(Integer id, MultipartFile file, String requestedFilename) throws IOException {
        User user = userRepository.findByIdAndIsDeletedFalse(id);
        if (user == null) {
            throw new IllegalArgumentException("User not found");
        }
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Avatar file is required");
        }

        Path avatarDir = Paths.get(uploadDir, "avatars").toAbsolutePath().normalize();
        Files.createDirectories(avatarDir);

        String filename = resolveUploadFilename(file, requestedFilename);
        if (filename == null || filename.isBlank()) {
            throw new IllegalArgumentException("Filename is required");
        }

        rejectRelativeParentPath(filename, "Filename cannot contain ../");
        if (isBlockedByBlacklist(filename)) {
            throw new IllegalArgumentException("This file type is not allowed");
        }

        Path destination = avatarDir.resolve(filename);
        if (destination.getParent() != null) {
            Files.createDirectories(destination.getParent());
        }

        file.transferTo(destination.toFile());

        /*
         * File upload fix:
         * Do not trust MultipartFile#getOriginalFilename() for the stored path.
         * Use a whitelist for image MIME types/extensions, generate a server-side
         * filename, keep the file inside avatarDir, and reject traversal:
         *
         * String contentType = file.getContentType();
         * if (contentType == null ||
         * !ALLOWED_IMAGE_TYPES.contains(contentType.toLowerCase(Locale.ROOT))) {
         * throw new IllegalArgumentException("Only images are allowed");
         * }
         *
         * String extension = getSafeImageExtension(contentType);
         * String safeFilename = UUID.randomUUID() + extension;
         * Path destination = avatarDir.resolve(safeFilename).normalize();
         * if (!destination.startsWith(avatarDir)) {
         * throw new IllegalArgumentException("Invalid upload path");
         * }
         *
         * file.transferTo(destination.toFile());
         * user.setAvatarUrl("/uploads/avatars/" + safeFilename);
         *
         * XXE/XMLDecoder chain fix:
         * This upload sink must not be able to write into imports/promotions.
         * /uploads/** owner checks only protect HTTP read-back; the promotion
         * importer reads files directly from disk. Keep the promotion import
         * directory outside user-writable upload paths, and make the importer
         * process only queue-service-generated filenames/job records.
         */

        user.setAvatarUrl("/uploads/avatars/" + filename);
        return userRepository.save(user);
    }

    private boolean isBlockedByBlacklist(String filename) {
        return BLOCKED_FILE_EXTENSIONS.stream().anyMatch(filename::endsWith);
    }

    private String resolveUploadFilename(MultipartFile file, String requestedFilename) {
        if (requestedFilename != null && !requestedFilename.isBlank()) {
            return requestedFilename.trim();
        }
        return file.getOriginalFilename();
    }

    private void rejectRelativeParentPath(String value, String message) {
        if (OBVIOUS_PARENT_TRAVERSAL.matcher(value).find()) {
            throw new IllegalArgumentException(message);
        }
    }
}
