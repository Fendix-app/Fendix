const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');

const CONTENT_DIR = path.resolve(process.cwd(), 'content');
const TERMS_FILE = 'terms-of-service.md';

const router = express.Router();

router.get('/', async (req, res) => {
  const content = await fs.readFile(path.join(CONTENT_DIR, TERMS_FILE), 'utf8'); // EVAL-SAFE
  res.json({ file: TERMS_FILE, content });
});

module.exports = router;
