const express = require('express');
const { ListObjectsV2Command, S3Client } = require('@aws-sdk/client-s3');
const { awsConfig } = require('../lib/hardcoded-secret-cross-file');

const s3 = new S3Client(awsConfig);

const router = express.Router();

router.get('/', async (req, res) => {
  const result = await s3.send(new ListObjectsV2Command({ Bucket: 'acme-reports' }));
  res.json((result.Contents ?? []).map((object) => object.Key));
});

module.exports = router;
