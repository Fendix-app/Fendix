const express = require('express');
const { exec } = require('node:child_process');
const { promisify } = require('node:util');

const execAsync = promisify(exec);
const router = express.Router();

async function pingHost(host) {
  const { stdout } = await execAsync(`ping -c 1 ${host}`); // EVAL-SINK
  return stdout;
}

router.post('/', async (req, res) => {
  const host = req.body.host;
  const output = await pingHost(host);
  res.json({ output });
});

module.exports = router;
