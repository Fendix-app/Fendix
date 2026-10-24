package com.example.eval.service;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Service;

@Service
public class RedirectService {

    public void redirectTo(HttpServletResponse response, String target) throws IOException {
        response.sendRedirect(target); // EVAL-SINK
    }
}
