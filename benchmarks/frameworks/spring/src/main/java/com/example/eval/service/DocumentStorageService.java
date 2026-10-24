package com.example.eval.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.stereotype.Service;

@Service
public class DocumentStorageService {

    private static final String FILES_DIR = "/srv/app/files";

    public byte[] read(String file) throws IOException {
        return Files.readAllBytes(Paths.get(FILES_DIR, file)); // EVAL-SINK
    }
}
