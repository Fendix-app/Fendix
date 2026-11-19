const express = require('express');

const router = express.Router();

router.get('/', async (req, res) => {
  const url = req.query.url;
  const upstream = await fetch(url); // EVAL-SINK
  res.json({ status: upstream.status, body: await upstream.text() });
});

module.exports = router;
