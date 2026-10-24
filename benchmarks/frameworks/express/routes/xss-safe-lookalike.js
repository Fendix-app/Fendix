const express = require('express');

const SITE_NAME = 'Acme Docs';

const router = express.Router();

router.get('/', (req, res) => {
  res.send(`<h1>Welcome to ${SITE_NAME}</h1>`); // EVAL-SAFE
});

module.exports = router;
