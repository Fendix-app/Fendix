package main

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"

	"example.com/eval/gin/internal/awsconfig"
)

func handleHardcodedSecretCrossFile(c *gin.Context) {
	ctx := c.Request.Context()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(awsconfig.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awsconfig.AccessKeyID, awsconfig.SecretAccessKey, "")),
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
