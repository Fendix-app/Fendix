package main

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"example.com/eval/nethttp/internal/awsconfig"
)

func handleHardcodedSecretCrossFile(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadDefaultConfig(r.Context(),
		config.WithRegion(awsconfig.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(awsconfig.AccessKeyID, awsconfig.SecretAccessKey, "")),
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
