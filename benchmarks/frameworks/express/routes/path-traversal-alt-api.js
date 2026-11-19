const express = require('express');
const fs = require('node:fs');
const path = require('node:path');

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

const router = express.Router();

router.get('/', (req, res) => {
  const file = req.query.file;
  const stream = fs.createReadStream(path.join(UPLOAD_DIR, file)); // EVAL-SINK
  res.type('application/octet-stream');
  stream.pipe(res);
});

module.exports = router;
