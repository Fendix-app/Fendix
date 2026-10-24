const express = require('express');

const router = express.Router();

router.get('/', (req, res) => {
  const returnTo = req.query.returnTo || '/';
  res.writeHead(302, { Location: returnTo }); // EVAL-SINK
  res.end();
});

module.exports = router;
