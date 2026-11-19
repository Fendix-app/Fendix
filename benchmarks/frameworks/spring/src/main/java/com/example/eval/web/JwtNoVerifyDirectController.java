package com.example.eval.web;

import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtNoVerifyDirectController {

    @GetMapping("/jwt-no-verify/direct")
    public ResponseEntity<Map<String, Object>> adminProfile(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization) {
        String token = authorization.replaceFirst("^Bearer ", "");
        DecodedJWT jwt;
        try {
            jwt = JWT.decode(token); // EVAL-SINK
        } catch (JWTDecodeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (!"admin".equals(jwt.getClaim("role").asString())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(Map.of("user", String.valueOf(jwt.getSubject()), "admin", true));
    }
}
