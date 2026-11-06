package com.example.eval.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WeakPasswordHashSafeLookalikeController {

    private static final String FILES_DIR = "/srv/app/files";

    @GetMapping("/weak-password-hash/safe-lookalike")
    public ResponseEntity<byte[]> catalog(@RequestHeader(value = HttpHeaders.IF_NONE_MATCH, required = false) String ifNoneMatch)
            throws IOException, NoSuchAlgorithmException {
        byte[] data = Files.readAllBytes(Paths.get(FILES_DIR, "catalog.json"));
        String etag = "\"" + HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(data)) + "\""; // EVAL-SAFE
        if (etag.equals(ifNoneMatch)) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(etag).build();
        }
        return ResponseEntity.ok().eTag(etag).contentType(MediaType.APPLICATION_JSON).body(data);
    }
}
