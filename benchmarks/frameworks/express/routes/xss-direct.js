const express = require('express');

const router = express.Router();

router.get('/', (req, res) => {
  const q = req.query.q;
  res.send(`<h1>Search results for ${q}</h1>`); // EVAL-SINK
});

module.exports = router;
