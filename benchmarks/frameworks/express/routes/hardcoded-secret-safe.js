const express = require('express');
const { ListObjectsV2Command, S3Client } = require('@aws-sdk/client-s3');

const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY; // EVAL-SAFE

const s3 = new S3Client({
  region: 'us-east-1',
  credentials: { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY },
});

const router = express.Router();

router.get('/', async (req, res) => {
  const result = await s3.send(new ListObjectsV2Command({ Bucket: 'acme-reports' }));
  res.json((result.Contents ?? []).map((object) => object.Key));
});

module.exports = router;
