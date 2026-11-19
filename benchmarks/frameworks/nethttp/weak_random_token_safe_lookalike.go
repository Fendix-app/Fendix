package main

import (
	"math/rand"
	"net/http"
)

var featuredProducts = []string{"sku-1001", "sku-1002", "sku-1003", "sku-1004", "sku-1005"}

func handleWeakRandomTokenSafeLookalike(w http.ResponseWriter, r *http.Request) {
	products := append([]string(nil), featuredProducts...)
	rand.Shuffle(len(products), func(i, j int) { products[i], products[j] = products[j], products[i] }) // EVAL-SAFE
	writeJSON(w, map[string][]string{"featured": products})
}
