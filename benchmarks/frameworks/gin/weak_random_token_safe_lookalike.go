package main

import (
	"math/rand"
	"net/http"

	"github.com/gin-gonic/gin"
)

var featuredProducts = []string{"sku-1001", "sku-1002", "sku-1003", "sku-1004", "sku-1005"}

func handleWeakRandomTokenSafeLookalike(c *gin.Context) {
	products := append([]string(nil), featuredProducts...)
	rand.Shuffle(len(products), func(i, j int) { products[i], products[j] = products[j], products[i] }) // EVAL-SAFE
	c.JSON(http.StatusOK, gin.H{"featured": products})
}
