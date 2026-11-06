const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

const router = express.Router();

router.get('/', async (req, res) => {
  const file = req.query.file;
  const filePath = path.resolve(UPLOAD_DIR, file);
  if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid file name' });
  }
  const content = await fs.readFile(filePath, 'utf8'); // EVAL-SAFE
  res.json({ file, content });
});

module.exports = router;
