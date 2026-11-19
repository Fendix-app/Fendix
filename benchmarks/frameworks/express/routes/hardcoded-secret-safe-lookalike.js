const express = require('express');

const BUILD_DIGEST = '4b7e19c2a05d83f6e2c8714b9d36fa057c1e48b2d9a3605f1e8bc274f30a96d5'; // EVAL-SAFE

const router = express.Router();

router.get('/', (req, res) => {
  res.json({ algorithm: 'sha256', digest: BUILD_DIGEST });
});

module.exports = router;
