package com.example.eval.web;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

import com.example.eval.service.RedirectService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpenRedirectCrossFileController {

    private final RedirectService redirectService;

    public OpenRedirectCrossFileController(RedirectService redirectService) {
        this.redirectService = redirectService;
    }

    @GetMapping("/open-redirect/cross-file")
    public void redirect(@RequestParam String next, HttpServletResponse response) throws IOException {
        redirectService.redirectTo(response, next);
    }
}
