package com.example.eval.web;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;

@RestController
public class HardcodedSecretDirectController {

    private static final String AWS_ACCESS_KEY_ID = "__EVAL_AWS_ACCESS_KEY_ID__"; // EVAL-SINK
    private static final String AWS_SECRET_ACCESS_KEY = "__EVAL_AWS_SECRET_ACCESS_KEY__";

    @GetMapping("/hardcoded-secret/direct")
    public List<String> listBuckets() {
        try (S3Client s3 = S3Client.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)))
                .build()) {
            return s3.listBuckets().buckets().stream().map(Bucket::name).toList();
        }
    }
}
