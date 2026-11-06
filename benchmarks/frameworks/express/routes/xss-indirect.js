const express = require('express');

const router = express.Router();

function renderResults(res, q) {
  res.send(`<h1>Search results for ${q}</h1>`); // EVAL-SINK
}

router.get('/', (req, res) => {
  const q = req.query.q;
  renderResults(res, q);
});

module.exports = router;
