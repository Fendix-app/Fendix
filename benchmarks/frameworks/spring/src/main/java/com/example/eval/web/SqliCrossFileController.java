package com.example.eval.web;

import java.util.List;
import java.util.Map;

import com.example.eval.service.UserDirectoryService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqliCrossFileController {

    private final UserDirectoryService userDirectoryService;

    public SqliCrossFileController(UserDirectoryService userDirectoryService) {
        this.userDirectoryService = userDirectoryService;
    }

    @GetMapping("/sqli/cross-file")
    public List<Map<String, Object>> searchUsers(@RequestParam String name) {
        return userDirectoryService.findByName(name);
    }
}
