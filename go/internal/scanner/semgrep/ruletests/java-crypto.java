package com.example.ruletests;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// ---------------------------------------------------------------- weak_password_hash

@RestController
class RegistrationController {

    private final PasswordEncoder passwordEncoder;

    RegistrationController(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    String register(@RequestParam String username, @RequestParam String password) throws Exception {
        // ruleid: java-weak_password_hash-taint
        return HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(password.getBytes(StandardCharsets.UTF_8)));
    }

    @PostMapping("/register-body")
    String registerBody(@RequestBody NewUser user) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        // ruleid: java-weak_password_hash-taint
        digest.update(user.getPassword().getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest.digest());
    }

    @PostMapping("/register-commons")
    String registerCommons(@RequestParam String pwd) {
        // ruleid: java-weak_password_hash-taint
        return DigestUtils.md5Hex(pwd);
    }

    String hashPassword(String rawPassword) throws Exception {
        // ruleid: java-weak_password_hash-taint
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA1").digest(rawPassword.getBytes(StandardCharsets.UTF_8)));
    }

    @PostMapping("/register-bcrypt")
    String registerBcrypt(@RequestParam String password) {
        // ok: java-weak_password_hash-taint
        return passwordEncoder.encode(password);
    }

    @GetMapping("/catalog")
    String catalogEtag() throws Exception {
        byte[] data = Files.readAllBytes(Paths.get("/srv/app/catalog.json"));
        // ok: java-weak_password_hash-taint
        return HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(data));
    }

    String checksum(String passwordPolicyDocument) throws Exception {
        // ok: java-weak_password_hash-taint
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(passwordPolicyDocument.getBytes(StandardCharsets.UTF_8)));
    }
}

class NewUser {
    private String password;

    String getPassword() {
        return password;
    }
}

// ---------------------------------------------------------------- jwt_no_verify

@RestController
class ProfileController {

    private final JWTVerifier verifier;
    private final Map<String, Algorithm> algorithmsByKeyId;

    ProfileController(JWTVerifier verifier, Map<String, Algorithm> algorithmsByKeyId) {
        this.verifier = verifier;
        this.algorithmsByKeyId = algorithmsByKeyId;
    }

    @GetMapping("/admin")
    boolean admin(@RequestHeader("Authorization") String authorization) {
        DecodedJWT jwt = JWT.decode(authorization.replaceFirst("^Bearer ", ""));
        // ruleid: java-jwt_no_verify-taint
        return "admin".equals(jwt.getClaim("role").asString());
    }

    @GetMapping("/whoami")
    String whoami(@RequestHeader("Authorization") String authorization) {
        DecodedJWT jwt = claimsOf(authorization.replaceFirst("^Bearer ", ""));
        // ruleid: java-jwt_no_verify-taint
        return jwt.getSubject();
    }

    private DecodedJWT claimsOf(String token) {
        return JWT.decode(token);
    }

    @GetMapping("/tenant")
    String tenant(@RequestHeader("Authorization") String authorization) {
        // ruleid: java-jwt_no_verify-taint
        Claims claims = Jwts.parser().parseClaimsJwt(authorization.substring(7)).getBody();
        return claims.get("tenant", String.class);
    }

    @GetMapping("/tenant-unsecured")
    String tenantUnsecured(@RequestHeader("Authorization") String authorization) {
        // ruleid: java-jwt_no_verify-taint
        return (String) Jwts.parser().build().parseUnsecuredClaims(authorization.substring(7)).getPayload().get("tenant");
    }

    // verify() throws unless the signature holds, so the decoded token passed
    // to it is verified once it returns.
    @GetMapping("/admin-verified-later")
    boolean adminVerifiedLater(@RequestHeader("Authorization") String authorization, Algorithm algorithm) {
        DecodedJWT jwt = JWT.decode(authorization.replaceFirst("^Bearer ", ""));
        JWT.require(algorithm).build().verify(jwt);
        // ok: java-jwt_no_verify-taint
        return "admin".equals(jwt.getClaim("role").asString());
    }

    @GetMapping("/admin-verified")
    boolean adminVerified(@RequestHeader("Authorization") String authorization) {
        DecodedJWT jwt = verifier.verify(authorization.replaceFirst("^Bearer ", ""));
        // ok: java-jwt_no_verify-taint
        return "admin".equals(jwt.getClaim("role").asString());
    }

    // The key id is read from the unverified header only to choose the key the
    // token is then verified with.
    @GetMapping("/admin-key-id")
    boolean adminKeyId(@RequestHeader("Authorization") String authorization) {
        String token = authorization.replaceFirst("^Bearer ", "");
        String keyId = JWT.decode(token).getKeyId();
        Algorithm algorithm = keyId == null ? null : algorithmsByKeyId.get(keyId);
        DecodedJWT jwt = JWT.require(algorithm).build().verify(token);
        // ok: java-jwt_no_verify-taint
        return "admin".equals(jwt.getClaim("role").asString());
    }
}

// ---------------------------------------------------------------- weak_random_token

@RestController
class ResetController {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final List<String> FEATURED = List.of("a", "b", "c");

    private final Random random = new Random();
    private final Random secureRandom = new SecureRandom();

    @PostMapping("/reset")
    String reset(@RequestParam String email) {
        // ruleid: java-weak_random_token-taint
        String token = new BigInteger(130, new Random()).toString(32);
        return email + token;
    }

    @PostMapping("/reset-code")
    String resetCode() {
        // ruleid: java-weak_random_token-taint
        String resetCode = String.format("%06d", random.nextInt(1_000_000));
        return resetCode;
    }

    @PostMapping("/otp")
    String otp() {
        // ruleid: java-weak_random_token-taint
        String otp = RandomStringUtils.randomNumeric(6);
        return otp;
    }

    String generateSessionToken() {
        // ruleid: java-weak_random_token-taint
        return Long.toHexString(Double.doubleToLongBits(Math.random()));
    }

    @PostMapping("/csrf")
    String csrf() {
        // ruleid: java-weak_random_token-taint
        String csrfToken = Long.toString(new Random().nextLong(), 36);
        return csrfToken;
    }

    @PostMapping("/session-secure")
    String sessionSecure() {
        // ok: java-weak_random_token-taint
        String sessionToken = Long.toString(secureRandom.nextLong(), 36);
        return sessionToken;
    }

    // The token is reported where it is drawn, not again where it is returned.
    String issueToken(String email) {
        // ruleid: java-weak_random_token-taint
        String token = Long.toHexString(random.nextLong());
        // ok: java-weak_random_token-taint
        return email + ":" + token;
    }

    @PostMapping("/reset-secure")
    String resetSecure() {
        // ok: java-weak_random_token-taint
        String token = new BigInteger(130, SECURE_RANDOM).toString(32);
        return token;
    }

    @PostMapping("/api-key-secure")
    String apiKeySecure() {
        // ok: java-weak_random_token-taint
        String apiKey = RandomStringUtils.secure().nextAlphanumeric(32);
        return apiKey;
    }

    @GetMapping("/featured")
    List<String> featured() {
        List<String> products = new ArrayList<>(FEATURED);
        // ok: java-weak_random_token-taint
        Collections.shuffle(products, new Random());
        return products;
    }

    @GetMapping("/jitter")
    int jitter() {
        // ok: java-weak_random_token-taint
        int delayMillis = new Random().nextInt(100);
        return delayMillis;
    }
}
