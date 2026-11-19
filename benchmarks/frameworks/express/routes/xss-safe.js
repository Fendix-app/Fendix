const express = require('express');
const escapeHtml = require('escape-html');

const router = express.Router();

router.get('/', (req, res) => {
  const q = req.query.q;
  res.send(`<h1>Search results for ${escapeHtml(q)}</h1>`); // EVAL-SAFE
});

module.exports = router;
