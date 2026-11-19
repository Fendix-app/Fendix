const axios = require('axios');
const express = require('express');

const router = express.Router();

router.get('/', async (req, res) => {
  const url = req.query.url;
  const upstream = await axios.get(url, { responseType: 'text' }); // EVAL-SINK
  res.json({ status: upstream.status, body: upstream.data });
});

module.exports = router;
