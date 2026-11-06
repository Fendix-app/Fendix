const express = require('express');

const router = express.Router();

async function fetchPreview(url) {
  const upstream = await fetch(url); // EVAL-SINK
  return { status: upstream.status, body: await upstream.text() };
}

router.get('/', async (req, res) => {
  const url = req.query.url;
  const preview = await fetchPreview(url);
  res.json(preview);
});

module.exports = router;
