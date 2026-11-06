const express = require('express');
const { pingHost } = require('../lib/cmdi-cross-file');

const router = express.Router();

router.post('/', async (req, res) => {
  const host = req.body.host;
  const output = await pingHost(host);
  res.json({ output });
});

module.exports = router;
