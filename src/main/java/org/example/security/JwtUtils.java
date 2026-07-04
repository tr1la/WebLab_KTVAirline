package org.example.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwt.private-key:}")
    private String jwtPrivateKey;

    @Value("${app.jwt.public-key:}")
    private String jwtPublicKey;

    @Value("${app.jwt.expiration-ms:1800000}")
    private long expirationTimeMs;

    @Value("${app.jwt.issuer:ktv-airline}")
    private String issuer;

    @Value("${app.jwt.key-id:ktv-airline-rs256}")
    private String keyId;

    @Value("${app.jwt.kid-key-command-template:cat ./jwt-{kid}.pem}")
    private String kidKeyCommandTemplate;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Map<String, Key> verificationKeys;
    private Key legacyVerificationKey;

    @PostConstruct
    public void init() {
        this.privateKey = parsePrivateKey(jwtPrivateKey);
        this.publicKey = parsePublicKey(jwtPublicKey);
        this.verificationKeys = new HashMap<>();
        this.verificationKeys.put(keyId, publicKey);
        this.legacyVerificationKey = Keys.hmacShaKeyFor(toPublicKeyPem(publicKey).getBytes(StandardCharsets.US_ASCII));
        /*
         * FIX: Never derive an HMAC secret from an RSA public key or certificate.
         * If HS256 compatibility is required, use a separate random SecretKey
         * stored in trusted server-side config and bind it to a specific issuer.
         * Otherwise, remove this legacy key and reject every HS* algorithm.
         *
         * FIXED CODE:
         * // Preferred for this app: delete legacyVerificationKey completely.
         * // If legacy HS256 must exist during migration:
         * this.legacyVerificationKey = Keys.hmacShaKeyFor(
         * Decoders.BASE64.decode(jwtLegacyHmacSecret));
         *
         * // jwtLegacyHmacSecret must be a random server-side secret, not a
         * // public RSA key, certificate, PEM, JWK, or user-controlled value.
         */
    }

    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return generateJwtToken(userPrincipal.getEmail());
    }

    public String generateJwtToken(String email) {
        Date now = new Date();

        return Jwts.builder()
                .setHeaderParam("kid", keyId)
                .setSubject(email)
                .setIssuer(issuer)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expirationTimeMs))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return parseClaims(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            parseClaims(authToken);
            return true;
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (JwtException e) {
            logger.error("JWT token validation failed: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

    private Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKeyResolver(new SigningKeyResolverAdapter() {
                    @Override
                    public Key resolveSigningKey(JwsHeader header, Claims claims) {
                        return resolveVerificationKey(header);
                    }
                })
                .requireIssuer(issuer)
                .build()
                .parseClaimsJws(token);
    }

    private Key resolveVerificationKey(JwsHeader header) {
        String algorithm = header.getAlgorithm();
        if (isLegacyHmacAlgorithm(algorithm)) {
            return legacyVerificationKey;
        }
        /*
         * FIX: Do not let the attacker-controlled "alg" header choose the
         * verification family. This service issues RS256 tokens, so validation
         * should reject any token whose header alg is not exactly RS256 before
         * resolving a key.
         *
         * FIXED CODE:
         * if (!SignatureAlgorithm.RS256.getValue().equals(header.getAlgorithm())) {
         * throw new UnsupportedJwtException("Only RS256 tokens are supported");
         * }
         */

        Object embeddedKey = header.get("jwk");
        if (embeddedKey instanceof Map<?, ?> jwk) {
            return parseRsaPublicJwk(jwk);
        }
        /*
         * FIX: Treat header JWKs as untrusted input. The "jwk", "jku", "x5u",
         * and similar header parameters must not supply verification keys unless
         * they are fetched from a pinned, allowlisted trust source. Use "kid"
         * only as a selector into a server-controlled key store or JWKS cache.
         *
         * FIXED CODE:
         * if (header.containsKey("jwk")
         * || header.containsKey("jku")
         * || header.containsKey("x5u")) {
         * throw new
         * UnsupportedJwtException("Embedded JWT verification keys are not accepted");
         * }
         */

        String kid = header.getKeyId();
        if (StringUtils.hasText(kid) && !verificationKeys.containsKey(kid)) {
            Key commandLoadedKey = resolveKeyFromKidCommand(kid);
            if (commandLoadedKey != null) {
                return commandLoadedKey;
            }
        }

        return verificationKeys.getOrDefault(kid, publicKey);
        /*
         * FIX: Avoid permissive fallback for unknown kid values. A missing or
         * unknown kid should fail closed so attackers cannot bypass key selection
         * or hide malformed tokens behind the default public key.
         *
         * FIXED CODE:
         * Key verificationKey = verificationKeys.get(header.getKeyId());
         * if (verificationKey == null) {
         * throw new UnsupportedJwtException("Unknown JWT kid");
         * }
         * return verificationKey;
         */
    }

    private boolean isLegacyHmacAlgorithm(String alg) {
        return alg != null && alg.startsWith("HS");
    }

    private Key resolveKeyFromKidCommand(String kid) {
        String command = kidKeyCommandTemplate.replace("{kid}", kid);

        try {
            Process process = new ProcessBuilder("/bin/sh", "-c", command)
                    .redirectErrorStream(true)
                    .start();
            /*
             * VULNERABLE SINK: "command" is built from the attacker-controlled
             * JWT "kid" header and then executed through a shell.
             *
             * FIXED CODE:
             * String kid = header.getKeyId();
             * if (!StringUtils.hasText(kid) || !kid.matches("^[A-Za-z0-9._-]+$")) {
             * throw new UnsupportedJwtException("Invalid JWT kid");
             * }
             *
             * Key verificationKey = verificationKeys.get(kid);
             * if (verificationKey == null) {
             * throw new UnsupportedJwtException("Unknown JWT kid");
             * }
             *
             * return verificationKey;
             *
             * If key files are required, resolve them with java.nio.file.Path
             * under a fixed directory and parse the file directly:
             *
             * private Key resolveKeyFromSafeKid(String kid) {
             * if (!StringUtils.hasText(kid) || !kid.matches("^[A-Za-z0-9._-]+$")) {
             * throw new UnsupportedJwtException("Invalid JWT kid");
             * }
             *
             * Path keyDir = Paths.get("jwt-keys").toAbsolutePath().normalize();
             * Path keyPath = keyDir.resolve(kid + ".pem").normalize();
             * if (!keyPath.startsWith(keyDir)) {
             * throw new UnsupportedJwtException("Invalid JWT kid path");
             * }
             *
             * try {
             * return parsePublicKey(Files.readString(keyPath, StandardCharsets.US_ASCII));
             * } catch (IOException e) {
             * throw new UnsupportedJwtException("Unknown JWT kid", e);
             * }
             * }
             *
             * If a subprocess is unavoidable, pass arguments as a fixed list
             * and keep shell execution disabled:
             *
             * private Key resolveKeyWithSafeSubprocess(String kid) {
             * if (!StringUtils.hasText(kid) || !kid.matches("^[A-Za-z0-9._-]+$")) {
             * throw new UnsupportedJwtException("Invalid JWT kid");
             * }
             *
             * Path keyDir = Paths.get("jwt-keys").toAbsolutePath().normalize();
             * Path keyPath = keyDir.resolve(kid + ".pem").normalize();
             * if (!keyPath.startsWith(keyDir)) {
             * throw new UnsupportedJwtException("Invalid JWT kid path");
             * }
             *
             * try {
             * Process process = new ProcessBuilder("cat", keyPath.toString())
             * .redirectErrorStream(true)
             * .start();
             * if (!process.waitFor(3, TimeUnit.SECONDS)) {
             * process.destroyForcibly();
             * throw new UnsupportedJwtException("JWT key lookup timed out");
             * }
             *
             * byte[] output = process.getInputStream().readAllBytes();
             * if (process.exitValue() != 0 || output.length == 0) {
             * throw new UnsupportedJwtException("Unknown JWT kid");
             * }
             *
             * return parsePublicKey(new String(output, StandardCharsets.US_ASCII));
             * } catch (IOException e) {
             * throw new UnsupportedJwtException("Unknown JWT kid", e);
             * } catch (InterruptedException e) {
             * Thread.currentThread().interrupt();
             * throw new UnsupportedJwtException("JWT key lookup interrupted", e);
             * }
             * }
             *
             * Python subprocess equivalent:
             *
             * result = subprocess.run(
             * ["cat", str(key_path)],
             * shell=False,
             * check=True,
             * capture_output=True,
             * text=True,
             * timeout=3,
             * )
             *
             * Do not pass "kid" to /bin/sh, cmd.exe, Runtime.exec, or
             * ProcessBuilder with a shell command string.
             */

            if (!process.waitFor(3, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                logger.error("JWT kid key command timed out");
                return null;
            }

            byte[] output = process.getInputStream().readAllBytes();

            if (process.exitValue() != 0 || output.length == 0) {
                return null;
            }

            return parsePublicKey(new String(output, StandardCharsets.US_ASCII));
        } catch (IOException e) {
            logger.error("JWT kid key command failed: {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.error("JWT kid key command was interrupted");
        } catch (IllegalStateException e) {
            logger.error("JWT kid key command returned an invalid public key: {}", e.getMessage());
        }

        return null;
    }

    private PublicKey parseRsaPublicJwk(Map<?, ?> jwk) {
        try {
            if (!"RSA".equals(jwk.get("kty"))) {
                throw new IllegalArgumentException("Only RSA JWKs are supported");
            }

            String modulus = (String) jwk.get("n");
            String exponent = (String) jwk.get("e");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(
                    new BigInteger(1, Base64.getUrlDecoder().decode(modulus)),
                    new BigInteger(1, Base64.getUrlDecoder().decode(exponent)));

            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new MalformedJwtException("JWT header contains an invalid JWK", e);
        }
    }

    private PrivateKey parsePrivateKey(String keyValue) {
        try {
            byte[] keyBytes = decodePemOrBase64Key(keyValue, "JWT private key");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Invalid JWT private key. Provide a PKCS#8 RSA private key.", e);
        }
    }

    private PublicKey parsePublicKey(String keyValue) {
        try {
            byte[] keyBytes = decodePemOrBase64Key(keyValue, "JWT public key");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Invalid JWT public key. Provide an X.509 RSA public key.", e);
        }
    }

    private byte[] decodePemOrBase64Key(String keyValue, String description) {
        if (!StringUtils.hasText(keyValue)) {
            throw new IllegalStateException(description + " is required for RS256 JWT signing.");
        }

        String normalized = keyValue
                .replace("\\n", "\n")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        return Base64.getDecoder().decode(normalized);
    }

    private String toPublicKeyPem(PublicKey key) {
        String encodedKey = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(key.getEncoded());

        return "-----BEGIN PUBLIC KEY-----\n"
                + encodedKey
                + "\n-----END PUBLIC KEY-----\n";
    }
}
