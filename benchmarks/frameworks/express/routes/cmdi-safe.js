const express = require('express');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const router = express.Router();

router.post('/', async (req, res) => {
  const host = req.body.host;
  const { stdout } = await execFileAsync('ping', ['-c', '1', host]); // EVAL-SAFE
  res.json({ output: stdout });
});

module.exports = router;
