const express = require('express');
const { fetchPreview } = require('../lib/ssrf-cross-file');

const router = express.Router();

router.get('/', async (req, res) => {
  const url = req.query.url;
  const preview = await fetchPreview(url);
  res.json(preview);
});

module.exports = router;
