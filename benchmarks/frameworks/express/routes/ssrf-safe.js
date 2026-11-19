const express = require('express');

const ALLOWED_HOSTS = new Set(['api.github.com', 'cdn.example.com']);

const router = express.Router();

router.get('/', async (req, res) => {
  const url = req.query.url;
  let target;
  try {
    target = new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {
    return res.status(400).json({ error: 'Host not allowed' });
  }
  const upstream = await fetch(target); // EVAL-SAFE
  res.json({ status: upstream.status, body: await upstream.text() });
});

module.exports = router;
