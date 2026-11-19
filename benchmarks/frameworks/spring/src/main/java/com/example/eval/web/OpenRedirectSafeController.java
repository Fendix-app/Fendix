package com.example.eval.web;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpenRedirectSafeController {

    @GetMapping("/open-redirect/safe")
    public void redirect(@RequestParam String next, HttpServletResponse response) throws IOException {
        String target = next;
        if (!target.startsWith("/") || target.startsWith("//") || target.startsWith("/\\")) {
            target = "/";
        }
        response.sendRedirect(target); // EVAL-SAFE
    }
}
