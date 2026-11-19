package com.example.eval.web;

import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
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
public class JwtNoVerifySafeController {

    private final JWTVerifier verifier;

    public JwtNoVerifySafeController(@Value("${JWT_SIGNING_KEY}") String signingKey) {
        this.verifier = JWT.require(Algorithm.HMAC256(signingKey)).build();
    }

    @GetMapping("/jwt-no-verify/safe")
    public ResponseEntity<Map<String, Object>> adminProfile(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization) {
        String token = authorization.replaceFirst("^Bearer ", "");
        DecodedJWT jwt;
        try {
            jwt = verifier.verify(token); // EVAL-SAFE
        } catch (JWTVerificationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!"admin".equals(jwt.getClaim("role").asString())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(Map.of("user", String.valueOf(jwt.getSubject()), "admin", true));
    }
}
