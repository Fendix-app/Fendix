const express = require('express');
const { renderResults } = require('../lib/xss-cross-file');

const router = express.Router();

router.get('/', (req, res) => {
  const q = req.query.q;
  renderResults(res, q);
});

module.exports = router;
