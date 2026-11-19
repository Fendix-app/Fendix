const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

const router = express.Router();

router.get('/', async (req, res) => {
  const file = req.query.file;
  const content = await fs.readFile(path.join(UPLOAD_DIR, file), 'utf8'); // EVAL-SINK
  res.json({ file, content });
});

module.exports = router;
