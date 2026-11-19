const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

const router = express.Router();

async function readUpload(file) {
  const content = await fs.readFile(path.join(UPLOAD_DIR, file), 'utf8'); // EVAL-SINK
  return content;
}

router.get('/', async (req, res) => {
  const file = req.query.file;
  const content = await readUpload(file);
  res.json({ file, content });
});

module.exports = router;
