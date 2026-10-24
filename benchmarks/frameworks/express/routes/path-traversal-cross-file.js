const express = require('express');
const { readUpload } = require('../lib/path-traversal-cross-file');

const router = express.Router();

router.get('/', async (req, res) => {
  const file = req.query.file;
  const content = await readUpload(file);
  res.json({ file, content });
});

module.exports = router;
