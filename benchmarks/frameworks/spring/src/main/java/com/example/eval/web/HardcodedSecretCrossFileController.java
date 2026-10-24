package com.example.eval.web;

import java.util.List;

import com.example.eval.config.AwsCredentials;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;

@RestController
public class HardcodedSecretCrossFileController {

    @GetMapping("/hardcoded-secret/cross-file")
    public List<String> listBuckets() {
        try (S3Client s3 = S3Client.builder()
                .region(Region.of(AwsCredentials.REGION))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(AwsCredentials.ACCESS_KEY_ID, AwsCredentials.SECRET_ACCESS_KEY)))
                .build()) {
            return s3.listBuckets().buckets().stream().map(Bucket::name).toList();
        }
    }
}
