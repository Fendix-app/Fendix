package com.example.eval.web;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WeakRandomTokenSafeLookalikeController {

    private static final List<String> FEATURED_PRODUCTS = List.of("sku-1001", "sku-1002", "sku-1003", "sku-1004", "sku-1005");

    @GetMapping("/weak-random-token/safe-lookalike")
    public Map<String, List<String>> featuredProducts() {
        List<String> products = new ArrayList<>(FEATURED_PRODUCTS);
        Collections.shuffle(products, new Random()); // EVAL-SAFE
        return Map.of("featured", products);
    }
}
