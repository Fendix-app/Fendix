const express = require('express');
const { execSync } = require('node:child_process');

const router = express.Router();

router.post('/', (req, res) => {
  const host = req.body.host;
  const output = execSync(`ping -c 1 ${host}`, { encoding: 'utf8' }); // EVAL-SINK
  res.json({ output });
});

module.exports = router;
