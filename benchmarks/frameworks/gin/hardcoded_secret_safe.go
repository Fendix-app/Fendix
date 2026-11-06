package main

import (
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
)

var (
	envAWSAccessKeyID     = os.Getenv("AWS_ACCESS_KEY_ID") // EVAL-SAFE
	envAWSSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
)

func handleHardcodedSecretSafe(c *gin.Context) {
	ctx := c.Request.Context()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(envAWSAccessKeyID, envAWSSecretAccessKey, "")),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "aws config failed"})
		return
	}

	out, err := s3.NewFromConfig(cfg).ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "list buckets failed"})
		return
	}
	names := make([]string, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		names = append(names, aws.ToString(b.Name))
	}
	c.JSON(http.StatusOK, gin.H{"buckets": names})
}
