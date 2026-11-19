package com.example.eval.web;

import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtNoVerifySafeLookalikeController {

    private final Map<String, Algorithm> algorithmsByKeyId;

    public JwtNoVerifySafeLookalikeController(
            @Value("${JWT_PRIMARY_KEY}") String primaryKey,
            @Value("${JWT_SECONDARY_KEY}") String secondaryKey) {
        this.algorithmsByKeyId = Map.of(
                "primary", Algorithm.HMAC256(primaryKey),
                "secondary", Algorithm.HMAC256(secondaryKey));
    }

    @GetMapping("/jwt-no-verify/safe-lookalike")
    public ResponseEntity<Map<String, Object>> adminProfile(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization) {
        String token = authorization.replaceFirst("^Bearer ", "");
        DecodedJWT jwt;
        try {
            String keyId = JWT.decode(token).getKeyId(); // EVAL-SAFE
            Algorithm algorithm = keyId == null ? null : algorithmsByKeyId.get(keyId);
            if (algorithm == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            jwt = JWT.require(algorithm).build().verify(token);
        } catch (JWTVerificationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!"admin".equals(jwt.getClaim("role").asString())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(Map.of("user", String.valueOf(jwt.getSubject()), "admin", true));
    }
}
