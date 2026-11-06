const express = require('express');

const router = express.Router();

router.get('/', (req, res) => {
  const q = req.query.q;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.write(`<h1>Search results for ${q}</h1>`); // EVAL-SINK
  res.end();
});

module.exports = router;
