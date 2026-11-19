package main

import (
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	envAWSAccessKeyID     = os.Getenv("AWS_ACCESS_KEY_ID") // EVAL-SAFE
	envAWSSecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
)

func handleHardcodedSecretSafe(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadDefaultConfig(r.Context(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(envAWSAccessKeyID, envAWSSecretAccessKey, "")),
	)
	if err != nil {
		http.Error(w, "aws config failed", http.StatusInternalServerError)
		return
	}

	out, err := s3.NewFromConfig(cfg).ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		http.Error(w, "list buckets failed", http.StatusBadGateway)
		return
	}
	names := make([]string, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		names = append(names, aws.ToString(b.Name))
	}
	writeJSON(w, map[string][]string{"buckets": names})
}
