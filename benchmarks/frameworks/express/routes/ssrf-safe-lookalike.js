const express = require('express');

const STATUS_URL = 'https://status.example.com/api/v2/status.json';

const router = express.Router();

router.get('/', async (req, res) => {
  const upstream = await fetch(STATUS_URL); // EVAL-SAFE
  res.json({ status: upstream.status, body: await upstream.text() });
});

module.exports = router;
