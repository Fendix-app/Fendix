const express = require('express');
const { exec } = require('node:child_process');
const { promisify } = require('node:util');

const execAsync = promisify(exec);
const router = express.Router();

router.post('/', async (req, res) => {
  const host = req.body.host;
  const { stdout } = await execAsync(`ping -c 1 ${host}`); // EVAL-SINK
  res.json({ output: stdout });
});

module.exports = router;
